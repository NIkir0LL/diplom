// Закрытие кастомного alert
function closeCustomAlert() {
    const alert = document.getElementById('custom-alert');
    if (alert) {
        alert.style.animation = 'popOut 0.2s ease-in';
        setTimeout(() => {
            alert.remove();
        }, 200);
        document.body.style.overflow = '';
    }
}

// Инициализация уведомлений
document.addEventListener('DOMContentLoaded', () => {
    const alert = document.getElementById('custom-alert');
    if (alert) {
        document.body.style.overflow = 'hidden';
        alert.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    }
});