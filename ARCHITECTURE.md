
# Процесс раздумья над архитектурой  

1. ### Мастер-ключ (Основа безопасности)  

Источник: Пользователь придумывает ключевую фразу при регистрации  
Хранение: НИ В КОЕМ СЛУЧАЕ не хранится ни на клиенте, ни на сервере  
Использование: Вводится пользователем при каждом входе в приложение  
Философия: Безопасность > Удобство  

**🔒 Критически важные дополнения:**
- **Entropy validation**: проверка силы мастер-фразы (минимум 128 бит энтропии)
- **Typo tolerance**: механизм исправления опечаток без снижения безопасности
- **Visual confirmation**: показ первых символов хэша для подтверждения правильности ввода
- **Rate limiting**: защита от brute force через exponential backoff

2. ### Безопасное кеширование на время сессии  

Web Crypto API:  
```javascript
// Импорт ключа в невыгружаемом формате
const cryptoKey = await crypto.subtle.importKey(
  "raw", 
  derivedKey, 
  { name: "AES-GCM" }, 
  false, // НЕ извлекаемый
  ["encrypt", "decrypt"]
);

// 🛡️ Дополнительная защита от race conditions
const keyManager = {
  key: null,
  mutex: new Mutex(),
  
  async getKey() {
    await this.mutex.acquire();
    try {
      if (!this.key) throw new Error('Key not available');
      return this.key;
    } finally {
      this.mutex.release();
    }
  }
};
```  

Дополнительные меры защиты:  
- Автоочистка через 15-30 минут неактивности  
- Очистка при закрытии вкладки/переходе на другую (Visibility API)  
- **🔥 Обфускация ключа в памяти** (разбивка на части + XOR с псевдослучайными данными)
- Защита от XSS через Content Security Policy  
- **🔥 Memory pressure monitoring**: детекция попыток memory exhaustion атак
- **🔥 DevTools detection**: блокировка при открытых инструментах разработчика
- **🔥 Constant-time operations**: защита от timing side-channel атак
 
3. ### Многоуровневая защита данных  

1. **Клиентское шифрование с защитой от side-channel атак**
- Все данные шифруются на клиенте перед отправкой  
- Алгоритм: AES-256-GCM (или ChaCha20-Poly1305)  
- Генерация ключей: **Argon2id** (не PBKDF2) из мастер-фразы + соль  
- **🛡️ Constant-time implementation**: защита от timing атак
- **🛡️ Blinding techniques**: скрытие промежуточных значений
- **🛡️ Random delays**: противодействие timing correlation

2. **Транспортная безопасность с максимальной защитой**
- Обязательный HTTPS/TLS 1.3+  
- Certificate pinning + Certificate Transparency monitoring
- Perfect Forward Secrecy  
- **🔥 DNS over HTTPS (DoH)**: защита от DNS poisoning
- **🔥 HTTP/3 + QUIC**: дополнительная защита от network-level атак
- **🔥 Traffic padding**: сокрытие размеров данных
- **🔥 Request timing randomization**: защита от traffic analysis

3. **Серверная защита (Zero-Knowledge)**
- Данные в БД остаются зашифрованными  
- Сервер физически не может расшифровать данные  
- Zero-knowledge архитектура  
- **🛡️ Encrypted database fields**: дополнительное server-side шифрование
- **🛡️ Data padding**: унификация размеров encrypted записей
- **🛡️ Audit logging**: детальное логирование всех операций

## Пошаговая архитектура  

1. **Регистрация пользователя**
- Пользователь создает аккаунт (email/username + пароль)  
- Обязательно: Пользователь придумывает мастер-фразу  
- **🔥 Entropy validation + strength meter**
- Из мастер-фразы генерируется криптографический ключ (Argon2id + уникальная соль)  
- **🔥 Hardware security module (HSM) для key derivation** (если доступно)
- Настройка социального восстановления  
- Настройка 2FA + **backup codes**
- **🔥 Initial security audit**: проверка устройства на malware

2. **Вход в систему**
- Стандартная аутентификация (email + пароль)  
- 2FA подтверждение (если настроено)  
- **🔥 Device fingerprinting**: детекция подозрительных устройств
- Обязательный ввод мастер-фразы  
- **🔥 Virtual keyboard**: защита от keyloggers
- **🔥 Anti-screenshot protection**: блокировка снимков экрана
- Генерация криптоключа из фразы  
- **🔥 Key derivation в WebWorker**: изоляция от main thread
- Безопасное кеширование в Web Crypto API  
- Запуск таймера автоочистки  
- **🔥 Session monitoring**: отслеживание подозрительной активности

3. **Работа с данными**

**Отправка данных:**  
- **🛡️ Pre-encryption validation**: проверка данных перед шифрованием
- Данные шифруются на клиенте перед HTTP запросом  
- **🔥 Chunked encryption**: разбивка больших файлов на части
- **🔥 Format-preserving encryption**: для структурированных данных
- Отправляются через защищенное соединение  
- **🔥 Request signing**: дополнительная аутентификация запросов
- Сохраняются в БД в зашифрованном виде  

**Получение данных:**  
- Зашифрованные данные приходят с сервера  
- **🛡️ Integrity verification**: проверка целостности данных
- Расшифровываются на клиенте кешированным ключом  
- **🔥 Decryption в изолированном context**: WebWorker или WASM
- **🛡️ Memory wiping**: очистка decrypted данных после использования
- Отображаются пользователю  

4. **Завершение сессии**
- При бездействии (15-30 мин) или закрытии вкладки  
- **🔥 Secure memory cleanup**: гарантированная очистка всех ключей
- **🛡️ Session invalidation**: аннулирование server-side сессии
- При следующем использовании - повторный ввод мастер-фразы  

## Риски и ограничения  

**Критические риски**
- Потеря мастер-фразы = потеря всех данных навсегда  
- XSS атаки могут перехватить фразу при вводе  
- Слабая мастер-фраза = уязвимость для brute force  
- **🔥 Supply chain attacks**: компрометация dependencies
- **🔥 Hardware-level attacks**: side-channel, rowhammer, cold boot
- **🔥 Social engineering**: атаки на доверенных лиц

**Технические ограничения**
- Невозможность поиска по зашифрованным данным (только точное совпадение)  
- Снижение производительности из-за постоянного шифрования/расшифровки  
- Сложность с индексированием в базе данных  
- **🔥 Browser compatibility**: ограничения Web Crypto API в старых браузерах
- **🔥 Mobile performance**: crypto операции могут разряжать батарею

**UX компромиссы**
- Необходимость ввода мастер-фразы при каждом входе  
- Невозможность "забыли пароль?" для восстановления данных  
- Сложность объяснения пользователям важности надежной фразы  
- **🔥 Security fatigue**: пользователи могут выбирать слабые фразы для удобства

## Первые шаги разработки  

1. **MVP**: Базовое шифрование с мастер-фразой и кешированием  
2. **v1.5**: Защита от основных векторов атак (XSS, timing, race conditions)
3. **v2**: Социальное восстановление через Shamir's Secret Sharing  
4. **v3**: Экспорт/импорт зашифрованных бэкапов  
5. **v4**: Продвинутые функции безопасности и аудит
6. **v5**: Hardware security integration (TPM, HSM, secure enclaves)

## 🚨 Критически важные моменты для реализации

### Защита от Race Conditions:
- Mutex/semaphore для всех crypto операций
- Atomic operations для critical sections
- Immutable crypto objects

### Защита от Memory Exhaustion:
- Memory quotas для crypto operations
- Priority-based allocation для keys
- Emergency cleanup procedures

### Защита от Side-Channel атак:
- Constant-time implementations
- Random delays и noise injection  
- Performance counter restrictions

### Защита от Network-Level атак:
- Certificate pinning + CT monitoring
- DNS over HTTPS (DoH)
- Traffic obfuscation techniques

**⚠️ Безопасность - это процесс, не состояние.**

- [Продвинутая Архитектура](ARCHITECTURE.md)  


...