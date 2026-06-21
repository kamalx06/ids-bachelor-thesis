var modal = document.getElementById("totpQrModal");
var verifyModal = document.getElementById("totpVerifyModal");
var verifyInput = document.getElementById("totpVerifyInput");
var verifyBtn = document.getElementById("totpVerifySubmit");
var closeBtn = document.getElementById("closeTotpQrModal");
var alertBox = document.getElementById("formAlert");
var disableTotpModal = document.getElementById("disableTotpModal");
var openDisableTotpModalBtn = document.getElementById("openDisableTotpModal");
var disableTotpPassword = document.getElementById("disableTotpPassword");
var disableTotpCode = document.getElementById("disableTotpCode");
var disableTotpConfirm = document.getElementById("disableTotpConfirm");
var emailOtpVerifyModal = document.getElementById("emailOtpVerifyModal");
var emailOtpVerifyInput = document.getElementById("emailOtpVerifyInput");
var emailOtpVerifySubmit = document.getElementById("emailOtpVerifySubmit");
var startEmailOtpEnableBtn = document.getElementById("startEmailOtpEnable");
var emailOtpDisableModal = document.getElementById("emailOtpDisableModal");
var openDisableEmailOtpModalBtn = document.getElementById("openDisableEmailOtpModal");
var emailOtpDisablePassword = document.getElementById("emailOtpDisablePassword");
var emailOtpDisableCode = document.getElementById("emailOtpDisableCode");
var emailOtpDisableConfirm = document.getElementById("emailOtpDisableConfirm");
var avatarInput = document.getElementById("avatarInput");
var avatarPreview = document.getElementById("avatarPreview");
var avatarInitials = document.getElementById("avatarInitials");

function getCsrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
}

function showAlert(msg, type) {
    if (!alertBox) return;
    alertBox.textContent = msg;
    alertBox.className = "alert " + type;
}

function openModal(modalEl) {
    if (!modalEl) return;
    modalEl.style.display = "flex";
}

function closeModal(modalEl) {
    if (!modalEl) return;
    modalEl.style.display = "none";
}

function hideQrShowVerify() {
    if (modal) {
        modal.style.display = "none";
    }
    if (verifyModal) {
        verifyModal.style.display = "flex";
        if (verifyInput) {
            verifyInput.value = "";
            verifyInput.focus();
        }
    }
}

async function handleVerifyClick() {
    if (!verifyInput) return;
    var code = (verifyInput.value || "").trim();
    if (!/^\d{6}$/.test(code)) {
        showAlert("OTP must be a 6-digit number.", "error");
        return;
    }

    verifyBtn.disabled = true;
    try {
        var res = await fetch("/verify_new_totp", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify({ otp: code })
        });

        var data = await res.json();
        if (data.ok) {
            showAlert("TOTP verified and enabled.", "info");
        } else {
            showAlert(data.error || "Invalid OTP. TOTP has been disabled.", "error");
        }

        setTimeout(function () {
            window.location.reload();
        }, 800);
    } catch (e) {
        showAlert("Verification failed, please try again.", "error");
    } finally {
        verifyBtn.disabled = false;
    }
}

if (closeBtn && modal) {
    closeBtn.addEventListener("click", function () {
        hideQrShowVerify();
    });
}

if (modal) {
    modal.addEventListener("click", function (e) {
        if (e.target === modal) {
            hideQrShowVerify();
        }
    });
}

if (verifyBtn) {
    verifyBtn.addEventListener("click", handleVerifyClick);
}

if (verifyInput) {
    verifyInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
            e.preventDefault();
            handleVerifyClick();
        }
    });
}

document.addEventListener("click", function (e) {
    var target = e.target;
    if (target && target.hasAttribute("data-close-modal")) {
        var id = target.getAttribute("data-close-modal");
        var m = document.getElementById(id);
        closeModal(m);
    }
});

if (openDisableTotpModalBtn && disableTotpModal) {
    openDisableTotpModalBtn.addEventListener("click", function () {
        if (disableTotpPassword) disableTotpPassword.value = "";
        if (disableTotpCode) disableTotpCode.value = "";
        openModal(disableTotpModal);
        if (disableTotpPassword) {
            disableTotpPassword.focus();
        }
    });
}

async function handleDisableTotp() {
    if (!disableTotpPassword || !disableTotpCode) return;
    var pwd = (disableTotpPassword.value || "").trim();
    var code = (disableTotpCode.value || "").trim();

    if (!pwd) {
        showAlert("Password is required to disable TOTP.", "error");
        return;
    }
    if (!/^\d{6}$/.test(code)) {
        showAlert("TOTP code must be a 6-digit number.", "error");
        return;
    }

    disableTotpConfirm.disabled = true;
    try {
        var res = await fetch("/disable_totp", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify({
                confirm_password: pwd,
                otp: code
            })
        });
        var data = await res.json();
        if (data.ok) {
            showAlert("TOTP has been disabled.", "info");
            closeModal(disableTotpModal);
            setTimeout(function () {
                window.location.reload();
            }, 800);
        } else {
            showAlert(data.error || "Failed to disable TOTP.", "error");
        }
    } catch (e) {
        showAlert("Request failed, please try again.", "error");
    } finally {
        disableTotpConfirm.disabled = false;
    }
}

if (disableTotpConfirm) {
    disableTotpConfirm.addEventListener("click", handleDisableTotp);
}

if (startEmailOtpEnableBtn) {
    startEmailOtpEnableBtn.addEventListener("click", async function () {
        if (startEmailOtpEnableBtn.disabled) return;
        startEmailOtpEnableBtn.disabled = true;
        try {
            var res = await fetch("/start_email_otp", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken()
                },
                body: JSON.stringify({})
            });
            var data = await res.json();
            if (data.ok) {
                showAlert("Verification code sent to your email.", "info");
                if (emailOtpVerifyModal) {
                    if (emailOtpVerifyInput) {
                        emailOtpVerifyInput.value = "";
                    }
                    openModal(emailOtpVerifyModal);
                    if (emailOtpVerifyInput) {
                        emailOtpVerifyInput.focus();
                    }
                }
            } else {
                showAlert(data.error || "Could not start email OTP setup.", "error");
            }
        } catch (e) {
            showAlert("Request failed, please try again.", "error");
        } finally {
            startEmailOtpEnableBtn.disabled = false;
        }
    });
}

async function handleVerifyEmailOtpEnable() {
    if (!emailOtpVerifyInput) return;
    var code = (emailOtpVerifyInput.value || "").trim();
    if (!/^\d{6}$/.test(code)) {
        showAlert("Code must be a 6-digit number.", "error");
        return;
    }

    emailOtpVerifySubmit.disabled = true;
    try {
        var res = await fetch("/verify_email_otp", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify({ otp: code })
        });
        var data = await res.json();
        if (data.ok) {
            showAlert("Email-based OTP enabled.", "info");
            closeModal(emailOtpVerifyModal);
            setTimeout(function () {
                window.location.reload();
            }, 800);
        } else {
            showAlert(data.error || "Invalid code.", "error");
        }
    } catch (e) {
        showAlert("Verification failed, please try again.", "error");
    } finally {
        emailOtpVerifySubmit.disabled = false;
    }
}

if (emailOtpVerifySubmit) {
    emailOtpVerifySubmit.addEventListener("click", handleVerifyEmailOtpEnable);
}
if (emailOtpVerifyInput) {
    emailOtpVerifyInput.addEventListener("keydown", function (e) {
        if (e.key === "Enter") {
            e.preventDefault();
            handleVerifyEmailOtpEnable();
        }
    });
}

if (openDisableEmailOtpModalBtn && emailOtpDisableModal) {
    openDisableEmailOtpModalBtn.addEventListener("click", async function () {
        if (openDisableEmailOtpModalBtn.disabled) return;
        openDisableEmailOtpModalBtn.disabled = true;
        try {
            var res = await fetch("/start_email_otp_disable", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRF-Token": getCsrfToken()
                },
                body: JSON.stringify({})
            });
            var data = await res.json();
            if (data.ok) {
                showAlert("Disable code sent to your email.", "info");
                if (emailOtpDisablePassword) emailOtpDisablePassword.value = "";
                if (emailOtpDisableCode) emailOtpDisableCode.value = "";
                openModal(emailOtpDisableModal);
                if (emailOtpDisablePassword) {
                    emailOtpDisablePassword.focus();
                }
            } else {
                showAlert(data.error || "Could not start email OTP disable flow.", "error");
            }
        } catch (e) {
            showAlert("Request failed, please try again.", "error");
        } finally {
            openDisableEmailOtpModalBtn.disabled = false;
        }
    });
}

async function handleDisableEmailOtp() {
    if (!emailOtpDisablePassword || !emailOtpDisableCode) return;
    var pwd = (emailOtpDisablePassword.value || "").trim();
    var code = (emailOtpDisableCode.value || "").trim();

    if (!pwd) {
        showAlert("Password is required to disable email OTP.", "error");
        return;
    }
    if (!/^\d{6}$/.test(code)) {
        showAlert("Code must be a 6-digit number.", "error");
        return;
    }

    emailOtpDisableConfirm.disabled = true;
    try {
        var res = await fetch("/disable_email_otp", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRF-Token": getCsrfToken()
            },
            body: JSON.stringify({
                confirm_password: pwd,
                otp: code
            })
        });
        var data = await res.json();
        if (data.ok) {
            showAlert("Email-based OTP disabled.", "info");
            closeModal(emailOtpDisableModal);
            setTimeout(function () {
                window.location.reload();
            }, 800);
        } else {
            showAlert(data.error || "Failed to disable email OTP.", "error");
        }
    } catch (e) {
        showAlert("Request failed, please try again.", "error");
    } finally {
        emailOtpDisableConfirm.disabled = false;
    }
}

if (emailOtpDisableConfirm) {
    emailOtpDisableConfirm.addEventListener("click", handleDisableEmailOtp);
}

if (avatarInput) {
    avatarInput.addEventListener("change", function (e) {
        var file = e.target.files && e.target.files[0];
        if (!file) {
            return;
        }
        if (!file.type.match(/^image\/(png|jpeg)$/)) {
            showAlert("Avatar must be a PNG or JPEG image.", "error");
            avatarInput.value = "";
            return;
        }
        var url = URL.createObjectURL(file);
        if (avatarPreview) {
            avatarPreview.src = url;
        } else if (avatarInitials) {
            var img = document.createElement("img");
            img.id = "avatarPreview";
            img.alt = "Profile picture";
            img.src = url;
            avatarInitials.replaceWith(img);
            avatarInitials = null;
            avatarPreview = img;
        }
    });
}

