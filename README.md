# Система подписания и хранения документов на Go

## О проекте
Этот модульный сервис предназначен для централизованного хранения и использования электронных подписей в корпоративной системе информационной безопасности. Он реализован с использованием микросервисной архитектуры и работает с несколькими базами данных MySQL.

## Основные функции
- Управление пользователями и их ролями.
- Хранение и использование электронных подписей.
- Генерация электронных ключей с помощью RSA и их сертификацией X.509
- Подписание документов с учетом политики безопасности.
- Аудит и логирование действий пользователей.
- HSM хранилище для загруженных данных

## Архитектура
- **Backend**: Go (Golang)
- **База данных**: MySQL (отдельные БД для пользователей и ключей/документов)
- **Хранение ключей**: Защищенные хранилища HSM
- **API**: REST/GRPC для взаимодействия с HSM

## Запуск проэкта
Для запуска проэкта необходимо:
1. создать бд с таблицами как в файле bd_structure
2. в файле main.go у web_server поменяйте ip и адрес к бд
3. в файле web_server/hsm/hsm.go поменяйте ip адрес сервиса
4. с начало запускаем HSM сервис, потом запускаем web_server
