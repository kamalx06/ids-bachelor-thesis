document.addEventListener("DOMContentLoaded", () => { 
    const form = document.getElementById("loginForm");
    const alertBox = document.getElementById("formAlert");
    const passwordStep = document.getElementById("passwordStep");
    const otpStepContainer = document.getElementById("otpStepContainer");
    const otpMethodModal = document.getElementById("otpMethodModal");
    const chooseTotpBtn = document.getElementById("chooseTotpMethod");
    const chooseEmailBtn = document.getElementById("chooseEmailMethod");
    const cancelOtpChoiceBtn = document.getElementById("cancelOtpChoice");
    const otpMaskedEmailSpan = document.getElementById("otpMaskedEmail");

    if (!form) return;
    
    let allowSubmit = false;

    function getCsrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.getAttribute("content") : "";
    }

    function showAlert(msg, type = "error") {
        if (!alertBox) return;
        alertBox.textContent = msg;
        alertBox.className = "alert " + type;
    }

    function clearAlert() {
        if (!alertBox) return;
        alertBox.textContent = "";
        alertBox.className = "";
    }

    function openOtpMethodModal() {
        if (!otpMethodModal) return;
        otpMethodModal.classList.remove("hidden");
        otpMethodModal.setAttribute("aria-hidden", "false");
    }

    function closeOtpMethodModal() {
        if (!otpMethodModal) return;
        otpMethodModal.classList.add("hidden");
        otpMethodModal.setAttribute("aria-hidden", "true");
    }

    // Built with DOM APIs (not innerHTML + template strings) so that a
    // username/password containing HTML-special characters (", <, &, ...)
    // can never be parsed as markup -- template-literal interpolation into
    // innerHTML here would have been a DOM XSS (and would silently corrupt
    // the hidden fields for any legitimate password containing a quote).
    function hiddenField(name, value) {
        const input = document.createElement("input");
        input.type = "hidden";
        input.name = name;
        input.value = value;
        return input;
    }

    function showTotpStep(username, password) {
        passwordStep.style.display = "none";
        otpStepContainer.innerHTML = "";

        const otpInput = document.createElement("input");
        otpInput.name = "otp";
        otpInput.placeholder = "Enter TOTP code";
        otpInput.pattern = "\\d{6}";
        otpInput.title = "6-digit OTP";
        otpInput.required = true;

        const submitBtn = document.createElement("button");
        submitBtn.type = "submit";
        submitBtn.textContent = "Login";

        otpStepContainer.append(
            hiddenField("username", username),
            hiddenField("password", password),
            hiddenField("otp_method", "totp"),
            otpInput,
            submitBtn
        );
    }

    function showEmailStep(username, password, maskedEmail) {
        passwordStep.style.display = "none";
        otpStepContainer.innerHTML = "";

        const info = document.createElement("p");
        info.className = "small";
        info.textContent = `Enter the 6-digit code sent to ${maskedEmail || "your email"}.`;

        const otpInput = document.createElement("input");
        otpInput.name = "otp";
        otpInput.placeholder = "Enter received code";
        otpInput.pattern = "\\d{6}";
        otpInput.title = "6-digit code";
        otpInput.required = true;

        const submitBtn = document.createElement("button");
        submitBtn.type = "submit";
        submitBtn.textContent = "Login";

        otpStepContainer.append(
            hiddenField("username", username),
            hiddenField("password", password),
            hiddenField("otp_method", "email"),
            info,
            otpInput,
            submitBtn
        );
    }

    async function startLoginEmailOtp(username, password) {
        const res = await fetch("/start_login_email_otp", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify({ username, password })
        });
        const data = await res.json();
        if (!res.ok || !data.ok) {
            throw new Error(data.error || "Failed to start email verification.");
        }
    }

    form.addEventListener("submit", async (e) => {
        if (allowSubmit) return;

        e.preventDefault();

        clearAlert();

        const btn = form.querySelector("button[type='submit']");
        btn.disabled = true;
        btn.textContent = "Processing...";

        const usernameInput = form.querySelector("input[name='username']");
        const passwordInput = form.querySelector("input[name='password']");

        let username = usernameInput.value.trim();
        let password = passwordInput.value;

        username = username.replace(/[\x00-\x1F\x7F]/g, "");
        username = username.normalize("NFKC");
        usernameInput.value = username;

        if (password.includes("\x00")) {
            showAlert("Invalid password characters detected.");
            btn.disabled = false;
            btn.textContent = "Next";
            return;
        }

        try {
            const res = await fetch("/check_totp", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken()
                },
                body: JSON.stringify({ username, password })
            });

            const data = await res.json();
            if (!res.ok) throw new Error(data.error || "Login failed");
            const totpRequired = !!data.totp_required;
            const emailOtpEnabled = !!data.email_otp_enabled;
            const maskedEmail = data.masked_email || "";

            if (!totpRequired && !emailOtpEnabled) {
                allowSubmit = true;
                form.submit();
                return;
            }

            if (totpRequired && !emailOtpEnabled) {
                showTotpStep(username, password);
                showAlert("TOTP required. Please enter your code.", "info");
                return;
            }

            if (emailOtpEnabled && !totpRequired) {
                await startLoginEmailOtp(username, password);
                showEmailStep(username, password, maskedEmail);
                showAlert("OTP code sent. Please check your inbox.", "info");
                return;
            }

            if (otpMethodModal && chooseTotpBtn && chooseEmailBtn) {
                if (otpMaskedEmailSpan) otpMaskedEmailSpan.textContent = maskedEmail;
                openOtpMethodModal();

                const onChooseTotp = () => {
                    closeOtpMethodModal();
                    removeListeners();
                    showTotpStep(username, password);
                    showAlert("TOTP required. Please enter your code.", "info");
                };

                const onChooseEmail = async () => {
                    try {
                        await startLoginEmailOtp(username, password);
                        closeOtpMethodModal();
                        removeListeners();
                        showEmailStep(username, password, maskedEmail);
                        showAlert("Email code sent. Please check your inbox.", "info");
                    } catch (err) {
                        closeOtpMethodModal();
                        removeListeners();
                        showAlert(err.message || "Failed to start email verification.", "error");
                    }
                };

                const onCancel = () => {
                    closeOtpMethodModal();
                    removeListeners();
                };

                function removeListeners() {
                    chooseTotpBtn.removeEventListener("click", onChooseTotp);
                    chooseEmailBtn.removeEventListener("click", onChooseEmail);
                    if (cancelOtpChoiceBtn) cancelOtpChoiceBtn.removeEventListener("click", onCancel);
                }

                chooseTotpBtn.addEventListener("click", onChooseTotp);
                chooseEmailBtn.addEventListener("click", onChooseEmail);
                if (cancelOtpChoiceBtn) cancelOtpChoiceBtn.addEventListener("click", onCancel);

            } else {
                if (totpRequired) {
                    showTotpStep(username, password);
                    showAlert("TOTP required. Please enter your code.", "info");
                } else {
                    await startLoginEmailOtp(username, password);
                    showEmailStep(username, password, maskedEmail);
                    showAlert("OTP code sent. Please check your inbox.", "info");
                }
            }

        } catch (err) {
            showAlert(err.message, "error");
        } finally {
            btn.disabled = false;
            btn.textContent = "Next";
        }
    });
});