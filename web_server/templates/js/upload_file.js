document.addEventListener('DOMContentLoaded', () => {
    const alert = document.getElementById('custom-alert');
    if (alert) {
        document.body.classList.add('alert-active');
    }
});

function closeCustomAlert() {
    const alert = document.getElementById('custom-alert');
    if (alert) {
        alert.style.animation = 'popOut 0.3s ease-in';
        setTimeout(() => {
            alert.remove();
            document.body.classList.remove('alert-active');
        }, 300);
    }
}