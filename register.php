<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $name = $_POST['name'];
    $phone = $_POST['phone'];
    $password = $_POST['password'];

    // Валидация данных
    if (empty($name) || empty($phone) || empty($password)) {
        die("Все поля должны быть заполнены");
    }

    if (strlen($phone) !== 11 || !is_numeric($phone)) {
        die("Номер телефона должен состоять из 11 цифр");
    }

    // Подключение к базе данных
    $conn = new mysqli('localhost', 'username', 'password', 'database_name');

    // Проверка соединения
    if ($conn->connect_error) {
        die("Ошибка подключения: " . $conn->connect_error);
    }

    // Хэширование пароля
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Вставка данных в базу данных
    $stmt = $conn->prepare("INSERT INTO users (name, phone, password) VALUES (?, ?, ?)");
    $stmt->bind_param("sss", $name, $phone, $hashed_password);

    if ($stmt->execute()) {
        // Перенаправление на страницу чатов
        header("Location: chats.html");
        exit();
    } else {
        echo "Ошибка: " . $stmt->error;
    }

    $stmt->close();
    $conn->close();

    session_start();
$_SESSION['user_name'] = $name;
header("Location: chats.html");

session_start();
echo "Добро пожаловать, " . $_SESSION['user_name'];
}
?>

