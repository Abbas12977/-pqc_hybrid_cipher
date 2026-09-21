#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace pqc {

// ==========================================================================
// استثناء مخصص لكل أخطاء طبقة التشفير
// ==========================================================================
class PQCException : public std::runtime_error {
public:
    explicit PQCException(const std::string& message) : std::runtime_error(message) {}
};

// ==========================================================================
// حاوية آمنة للبيانات الحساسة (مفاتيح، أسرار مشتركة)
// تُصفَّر البيانات تلقائياً من الذاكرة عند تدمير الكائن أو نقله
// ==========================================================================
class SecureBuffer {
public:
    SecureBuffer() = default;
    explicit SecureBuffer(size_t size);
    SecureBuffer(const uint8_t* data, size_t size);

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    ~SecureBuffer();

    uint8_t* data() { return data_.data(); }
    const uint8_t* data() const { return data_.data(); }
    size_t size() const { return data_.size(); }
    bool empty() const { return data_.empty(); }
    void resize(size_t new_size);

private:
    std::vector<uint8_t> data_;
};

struct KeyPair {
    std::vector<uint8_t> public_key;
    SecureBuffer secret_key;
};

struct EncapsResult {
    std::vector<uint8_t> ciphertext;  // نص Kyber المشفّر (يُرسل مع الرسالة)
    SecureBuffer shared_secret;       // السر المشترك (يُشتق منه مفتاح AES عبر HKDF)
};

// ==========================================================================
// غلاف (wrapper) حول خوارزمية Kyber / ML-KEM من مكتبة liboqs
// ==========================================================================
class KyberKEM {
public:
    // algorithm: "Kyber512" | "Kyber768" | "Kyber1024"
    // (يدعم تلقائياً الأسماء البديلة ML-KEM-512/768/1024 حسب نسخة liboqs المثبتة)
    explicit KyberKEM(const std::string& algorithm = "Kyber768");
    ~KyberKEM();

    KyberKEM(const KyberKEM&) = delete;
    KyberKEM& operator=(const KyberKEM&) = delete;

    KeyPair generate_keypair() const;
    EncapsResult encapsulate(const std::vector<uint8_t>& public_key) const;
    SecureBuffer decapsulate(const std::vector<uint8_t>& ciphertext,
                              const SecureBuffer& secret_key) const;

    size_t public_key_length() const;
    size_t secret_key_length() const;
    size_t ciphertext_length() const;
    size_t shared_secret_length() const;
    const std::string& algorithm_name() const { return algorithm_; }

private:
    std::string algorithm_;
    void* kem_ = nullptr;  // OQS_KEM* (مخفي عن الهيدر لتقليل الاعتمادية)
};

// ==========================================================================
// طبقة AES-256-GCM المتماثلة (النمط "دفعة واحدة" - مناسب للرسائل القصيرة)
// ==========================================================================
class AesGcm {
public:
    static constexpr size_t KEY_LEN = 32;    // 256-bit
    static constexpr size_t NONCE_LEN = 12;  // 96-bit، الموصى به لـ GCM
    static constexpr size_t TAG_LEN = 16;    // 128-bit

    struct Sealed {
        std::vector<uint8_t> nonce;
        std::vector<uint8_t> tag;
        std::vector<uint8_t> ciphertext;
    };

    static Sealed encrypt(const uint8_t* key, size_t key_len, const uint8_t* plaintext,
                           size_t plaintext_len);

    static std::vector<uint8_t> decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce,
                                         size_t nonce_len, const uint8_t* tag, size_t tag_len,
                                         const uint8_t* ciphertext, size_t ciphertext_len);
};

// ==========================================================================
// طبقة AES-256-GCM بنمط البث (Streaming) - مناسبة للملفات الكبيرة جداً
// تعالج البيانات على دفعات (chunks) دون الحاجة لتحميلها كاملة بالذاكرة
// ==========================================================================
class AesGcmStream {
public:
    enum class Mode { Encrypt, Decrypt };

    AesGcmStream(Mode mode, const uint8_t* key, size_t key_len, const uint8_t* nonce,
                 size_t nonce_len);
    ~AesGcmStream();

    AesGcmStream(const AesGcmStream&) = delete;
    AesGcmStream& operator=(const AesGcmStream&) = delete;

    // يعالج كتلة بيانات واحدة. out يجب أن يكون بحجم in_len على الأقل.
    // يُرجع عدد البايتات المكتوبة فعلياً في out.
    size_t update(const uint8_t* in, size_t in_len, uint8_t* out);

    // (وضع التشفير فقط) ينهي العملية ويُرجع رمز المصادقة (tag)
    std::vector<uint8_t> finalize_encrypt();

    // (وضع فك التشفير فقط) يضبط رمز المصادقة المتوقع وينهي مع التحقق منه.
    // يرمي PQCException إذا فشل التحقق (بيانات مُتلاعَب بها أو مفتاح خاطئ).
    void finalize_decrypt(const uint8_t* tag, size_t tag_len);

private:
    void* ctx_ = nullptr;  // EVP_CIPHER_CTX*
    Mode mode_;
};

// ==========================================================================
// الطبقة العليا: تشفير هجين = Kyber KEM + HKDF-SHA256 + AES-256-GCM
// - encrypt_bytes/decrypt_bytes: للرسائل القصيرة (تُعالَج كاملة بالذاكرة)
// - encrypt_file/decrypt_file: للملفات (تُعالَج بالبث، تدعم أي حجم عملياً)
// ==========================================================================
class HybridCipher {
public:
    explicit HybridCipher(const std::string& kyber_algorithm = "Kyber768");

    void generate_keys(const std::string& public_key_path,
                        const std::string& secret_key_path) const;

    void encrypt_file(const std::string& input_path, const std::string& output_path,
                       const std::string& public_key_path) const;

    void decrypt_file(const std::string& input_path, const std::string& output_path,
                       const std::string& secret_key_path) const;

    std::vector<uint8_t> encrypt_bytes(const std::vector<uint8_t>& plaintext,
                                        const std::vector<uint8_t>& public_key) const;

    std::vector<uint8_t> decrypt_bytes(const std::vector<uint8_t>& packed,
                                        const SecureBuffer& secret_key) const;

private:
    KyberKEM kem_;
};

// ==========================================================================
// أدوات مساعدة (I/O)
// ==========================================================================
std::vector<uint8_t> read_file_bytes(const std::string& path);
void write_file_bytes(const std::string& path, const uint8_t* data, size_t len);
// تقرأ ملفاً حساساً (مثل مفتاح خاص) مباشرة إلى SecureBuffer وتمسح أي نسخة
// وسيطة من الذاكرة العادية فوراً بعد النسخ.
SecureBuffer read_file_secure(const std::string& path);
// حجم الملف بالبايت دون تحميل محتواه بالذاكرة.
uint64_t file_size(const std::string& path);
std::string bytes_to_hex(const uint8_t* data, size_t len);

}  // namespace pqc