// Загрузка ключей для выбранного пользователя
function loadKeys() {
    const userID = document.getElementById("user_id").value;
    const xhr = new XMLHttpRequest();
    xhr.open("GET", "/get_user_keys?user_id=" + userID, true);
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            const keys = JSON.parse(xhr.responseText);
            const keySelect = document.getElementById("bank_id");
            if (keySelect) {
                keySelect.innerHTML = "";
                keys.forEach(function (key) {
                    const option = document.createElement("option");
                    option.value = key.ID;
                    option.text = key.Bank;
                    keySelect.add(option);
                });
            }
        }
    };
    xhr.send();
}

// Закрытие кастомного алерта
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

// Инициализация уведомлений
document.addEventListener('DOMContentLoaded', () => {
    const alert = document.getElementById('custom-alert');
    if (alert) {
        document.body.classList.add('alert-active');
    }
});