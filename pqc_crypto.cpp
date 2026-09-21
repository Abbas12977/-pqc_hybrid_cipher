#include "pqc_crypto.hpp"

#include <oqs/oqs.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <utility>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace pqc {

namespace {

constexpr size_t HASH_LEN = 32;              // طول مخرجات SHA-256
constexpr size_t PQC_CHUNK_SIZE = 1u << 16;  // 64KB لكل دفعة أثناء بث الملفات

// مسح آمن للذاكرة (يمنع المترجم من حذف العملية كـ "غير مستخدمة")
void secure_zero(void* ptr, size_t len) {
    if (ptr && len > 0) {
        volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
        while (len--) {
            *p++ = 0;
        }
    }
}

// يستخرج آخر خطأ من ستاك أخطاء OpenSSL كنص، ثم يمسح الستاك.
// بدون هذا، فشل أي دالة OpenSSL يُترجم لرسالة عامة غير مفيدة للتشخيص.
std::string openssl_error_string() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "(لا تفاصيل إضافية من OpenSSL)";
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    ERR_clear_error();
    return std::string(buf);
}

// اشتقاق مفتاح AES-256 من السر المشترك عبر HKDF-SHA256 (RFC 5869)
// إضافة هذه الطبقة أفضل من استخدام سر Kyber مباشرة كمفتاح AES: تفصل السياق
// (Domain Separation) وتتبع أفضل الممارسات في الأنظمة الهجينة الحقيقية.
std::array<uint8_t, HASH_LEN> hkdf_sha256_derive(const uint8_t* ikm, size_t ikm_len,
                                                  const std::string& info) {
    unsigned char prk[HASH_LEN];
    unsigned int prk_len = 0;

    // HKDF-Extract: PRK = HMAC-SHA256(salt="" , IKM)
    if (HMAC(EVP_sha256(), nullptr, 0, ikm, ikm_len, prk, &prk_len) == nullptr ||
        prk_len != HASH_LEN) {
        throw PQCException("فشل اشتقاق المفتاح (HKDF-Extract): " + openssl_error_string());
    }

    // HKDF-Expand: OKM = HMAC-SHA256(PRK, info || 0x01)  [كتلة واحدة تكفي لأن HashLen == 32]
    // ملاحظة: expand_input يحتوي فقط على نص تسمية عام ثابت (info) وليس أي سر —
    // لكن نمسحه أيضاً كإجراء احترازي إضافي (defense-in-depth) لا يكلف شيئاً.
    std::vector<uint8_t> expand_input(info.begin(), info.end());
    expand_input.push_back(0x01);

    unsigned char okm[HASH_LEN];
    unsigned int okm_len = 0;
    bool ok = (HMAC(EVP_sha256(), prk, static_cast<int>(HASH_LEN), expand_input.data(),
                     expand_input.size(), okm, &okm_len) != nullptr) &&
              (okm_len == HASH_LEN);

    secure_zero(expand_input.data(), expand_input.size());

    if (!ok) {
        secure_zero(prk, HASH_LEN);
        throw PQCException("فشل اشتقاق المفتاح (HKDF-Expand): " + openssl_error_string());
    }

    std::array<uint8_t, HASH_LEN> result{};
    std::copy(okm, okm + HASH_LEN, result.begin());

    secure_zero(prk, HASH_LEN);
    secure_zero(okm, HASH_LEN);
    return result;
}

}  // namespace

// ==========================================================================
// SecureBuffer
// ==========================================================================
SecureBuffer::SecureBuffer(size_t size) : data_(size, 0) {}

SecureBuffer::SecureBuffer(const uint8_t* data, size_t size) : data_(data, data + size) {}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept : data_(std::move(other.data_)) {
    other.data_.clear();
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (!data_.empty()) {
            secure_zero(data_.data(), data_.size());
        }
        data_ = std::move(other.data_);
        other.data_.clear();
    }
    return *this;
}

SecureBuffer::~SecureBuffer() {
    if (!data_.empty()) {
        secure_zero(data_.data(), data_.size());
    }
}

void SecureBuffer::resize(size_t new_size) { data_.resize(new_size, 0); }

// ==========================================================================
// KyberKEM
// ==========================================================================
KyberKEM::KyberKEM(const std::string& algorithm) : algorithm_(algorithm) {
    OQS_KEM* kem = OQS_KEM_new(algorithm.c_str());

    if (!kem) {
        // نسخ مختلفة من liboqs تستخدم إما التسمية القديمة "KyberXXX" أو التسمية
        // القياسية الرسمية NIST "ML-KEM-XXX". نجرب البديل تلقائياً لزيادة التوافقية.
        static const std::vector<std::pair<std::string, std::string>> aliases = {
            {"Kyber512", "ML-KEM-512"},   {"Kyber768", "ML-KEM-768"},
            {"Kyber1024", "ML-KEM-1024"}, {"ML-KEM-512", "Kyber512"},
            {"ML-KEM-768", "Kyber768"},   {"ML-KEM-1024", "Kyber1024"},
        };
        for (const auto& pair : aliases) {
            if (algorithm == pair.first) {
                kem = OQS_KEM_new(pair.second.c_str());
                if (kem) {
                    algorithm_ = pair.second;
                    break;
                }
            }
        }
    }

    if (!kem) {
        throw PQCException(
            "فشل تهيئة خوارزمية '" + algorithm +
            "'. غير مدعومة في نسخة liboqs المثبتة على جهازك. "
            "تأكد من بناء liboqs مع تفعيل دعم Kyber/ML-KEM (مفعّل افتراضياً).");
    }

    kem_ = kem;
}

KyberKEM::~KyberKEM() {
    if (kem_) {
        OQS_KEM_free(reinterpret_cast<OQS_KEM*>(kem_));
        kem_ = nullptr;
    }
}

KeyPair KyberKEM::generate_keypair() const {
    auto* kem = reinterpret_cast<OQS_KEM*>(kem_);

    KeyPair kp;
    kp.public_key.resize(kem->length_public_key);
    kp.secret_key.resize(kem->length_secret_key);

    OQS_STATUS rc = OQS_KEM_keypair(kem, kp.public_key.data(), kp.secret_key.data());
    if (rc != OQS_SUCCESS) {
        throw PQCException("فشل توليد زوج المفاتيح (OQS_KEM_keypair فشلت).");
    }
    return kp;
}

EncapsResult KyberKEM::encapsulate(const std::vector<uint8_t>& public_key) const {
    auto* kem = reinterpret_cast<OQS_KEM*>(kem_);

    if (public_key.empty()) {
        throw PQCException("المفتاح العام فارغ.");
    }
    if (public_key.size() != kem->length_public_key) {
        throw PQCException("حجم المفتاح العام غير صحيح. المتوقع " +
                            std::to_string(kem->length_public_key) + " بايت، والمُستلم " +
                            std::to_string(public_key.size()) + " بايت.");
    }

    EncapsResult result;
    result.ciphertext.resize(kem->length_ciphertext);
    result.shared_secret.resize(kem->length_shared_secret);

    OQS_STATUS rc = OQS_KEM_encaps(kem, result.ciphertext.data(), result.shared_secret.data(),
                                    public_key.data());
    if (rc != OQS_SUCCESS) {
        throw PQCException("فشلت عملية التغليف (encapsulation) الخاصة بـ Kyber.");
    }
    return result;
}

SecureBuffer KyberKEM::decapsulate(const std::vector<uint8_t>& ciphertext,
                                    const SecureBuffer& secret_key) const {
    auto* kem = reinterpret_cast<OQS_KEM*>(kem_);

    if (ciphertext.size() != kem->length_ciphertext) {
        throw PQCException("حجم نص Kyber المشفر غير صحيح (الملف تالف أو خوارزمية مختلفة).");
    }
    if (secret_key.size() != kem->length_secret_key) {
        throw PQCException("حجم المفتاح الخاص غير صحيح — تأكد أنك تستخدم المفتاح الصحيح.");
    }

    SecureBuffer shared_secret(kem->length_shared_secret);
    OQS_STATUS rc =
        OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), secret_key.data());
    if (rc != OQS_SUCCESS) {
        throw PQCException(
            "فشلت عملية فك التغليف (decapsulation) — المفتاح الخاص أو البيانات غير صالحة.");
    }
    return shared_secret;
}

size_t KyberKEM::public_key_length() const {
    return reinterpret_cast<OQS_KEM*>(kem_)->length_public_key;
}
size_t KyberKEM::secret_key_length() const {
    return reinterpret_cast<OQS_KEM*>(kem_)->length_secret_key;
}
size_t KyberKEM::ciphertext_length() const {
    return reinterpret_cast<OQS_KEM*>(kem_)->length_ciphertext;
}
size_t KyberKEM::shared_secret_length() const {
    return reinterpret_cast<OQS_KEM*>(kem_)->length_shared_secret;
}

// ==========================================================================
// AesGcm (دفعة واحدة - للرسائل القصيرة)
// ==========================================================================
namespace {
struct EvpCtxGuard {
    EVP_CIPHER_CTX* ctx;
    explicit EvpCtxGuard(EVP_CIPHER_CTX* c) : ctx(c) {}
    ~EvpCtxGuard() {
        if (ctx) EVP_CIPHER_CTX_free(ctx);
    }
    EvpCtxGuard(const EvpCtxGuard&) = delete;
    EvpCtxGuard& operator=(const EvpCtxGuard&) = delete;
};
}  // namespace

AesGcm::Sealed AesGcm::encrypt(const uint8_t* key, size_t key_len, const uint8_t* plaintext,
                                size_t plaintext_len) {
    if (!key || key_len != KEY_LEN) {
        throw PQCException("طول مفتاح AES غير صحيح، يجب أن يكون 32 بايت (256-بت).");
    }
    if (plaintext_len > 0 && !plaintext) {
        throw PQCException("مؤشر النص الصريح فارغ رغم أن الطول أكبر من صفر.");
    }

    Sealed sealed;
    sealed.nonce.resize(NONCE_LEN);
    if (RAND_bytes(sealed.nonce.data(), static_cast<int>(NONCE_LEN)) != 1) {
        throw PQCException("فشل توليد nonce عشوائي آمن: " + openssl_error_string());
    }

    EVP_CIPHER_CTX* raw_ctx = EVP_CIPHER_CTX_new();
    if (!raw_ctx) {
        throw PQCException("فشل إنشاء سياق التشفير: " + openssl_error_string());
    }
    EvpCtxGuard guard(raw_ctx);

    if (EVP_EncryptInit_ex(raw_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw PQCException("فشل تهيئة خوارزمية AES-256-GCM: " + openssl_error_string());
    }
    if (EVP_CIPHER_CTX_ctrl(raw_ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(NONCE_LEN),
                             nullptr) != 1) {
        throw PQCException("فشل ضبط طول IV: " + openssl_error_string());
    }
    if (EVP_EncryptInit_ex(raw_ctx, nullptr, nullptr, key, sealed.nonce.data()) != 1) {
        throw PQCException("فشل تهيئة المفتاح والـ IV: " + openssl_error_string());
    }

    std::vector<uint8_t> outbuf(plaintext_len > 0 ? plaintext_len : 1);
    int out_len = 0;
    int total_len = 0;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(raw_ctx, outbuf.data(), &out_len, plaintext,
                               static_cast<int>(plaintext_len)) != 1) {
            throw PQCException("فشل أثناء عملية التشفير: " + openssl_error_string());
        }
        total_len += out_len;
    }

    if (EVP_EncryptFinal_ex(raw_ctx, outbuf.data() + total_len, &out_len) != 1) {
        throw PQCException("فشل إنهاء عملية التشفير: " + openssl_error_string());
    }
    total_len += out_len;

    sealed.ciphertext.assign(outbuf.begin(), outbuf.begin() + total_len);

    sealed.tag.resize(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(raw_ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(TAG_LEN),
                             sealed.tag.data()) != 1) {
        throw PQCException("فشل استخراج رمز المصادقة: " + openssl_error_string());
    }

    return sealed;
}

std::vector<uint8_t> AesGcm::decrypt(const uint8_t* key, size_t key_len, const uint8_t* nonce,
                                      size_t nonce_len, const uint8_t* tag, size_t tag_len,
                                      const uint8_t* ciphertext, size_t ciphertext_len) {
    if (!key || key_len != KEY_LEN) {
        throw PQCException("طول مفتاح AES غير صحيح.");
    }
    if (!nonce || nonce_len != NONCE_LEN) {
        throw PQCException("طول nonce غير صحيح.");
    }
    if (!tag || tag_len != TAG_LEN) {
        throw PQCException("طول رمز المصادقة (tag) غير صحيح.");
    }
    if (ciphertext_len > 0 && !ciphertext) {
        throw PQCException("مؤشر النص المشفر فارغ رغم أن الطول أكبر من صفر.");
    }

    EVP_CIPHER_CTX* raw_ctx = EVP_CIPHER_CTX_new();
    if (!raw_ctx) {
        throw PQCException("فشل إنشاء سياق فك التشفير: " + openssl_error_string());
    }
    EvpCtxGuard guard(raw_ctx);

    if (EVP_DecryptInit_ex(raw_ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        throw PQCException("فشل تهيئة AES-256-GCM لفك التشفير: " + openssl_error_string());
    }
    if (EVP_CIPHER_CTX_ctrl(raw_ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_len),
                             nullptr) != 1) {
        throw PQCException("فشل ضبط طول IV لفك التشفير: " + openssl_error_string());
    }
    if (EVP_DecryptInit_ex(raw_ctx, nullptr, nullptr, key, nonce) != 1) {
        throw PQCException("فشل تهيئة المفتاح والـ IV لفك التشفير: " + openssl_error_string());
    }

    std::vector<uint8_t> outbuf(ciphertext_len > 0 ? ciphertext_len : 1);
    int out_len = 0;
    int total_len = 0;

    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(raw_ctx, outbuf.data(), &out_len, ciphertext,
                               static_cast<int>(ciphertext_len)) != 1) {
            throw PQCException("فشل أثناء عملية فك التشفير: " + openssl_error_string());
        }
        total_len += out_len;
    }

    if (EVP_CIPHER_CTX_ctrl(raw_ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len),
                             const_cast<uint8_t*>(tag)) != 1) {
        throw PQCException("فشل ضبط رمز المصادقة قبل التحقق: " + openssl_error_string());
    }

    int verify_rc = EVP_DecryptFinal_ex(raw_ctx, outbuf.data() + total_len, &out_len);
    if (verify_rc <= 0) {
        secure_zero(outbuf.data(), outbuf.size());
        throw PQCException(
            "فشل التحقق من سلامة البيانات (Authentication Failed) — "
            "الملف تالف أو تم التلاعب به أو المفتاح غير صحيح.");
    }
    total_len += out_len;

    std::vector<uint8_t> result(outbuf.begin(), outbuf.begin() + total_len);
    secure_zero(outbuf.data(), outbuf.size());
    return result;
}

// ==========================================================================
// AesGcmStream (بث - للملفات)
// ==========================================================================
AesGcmStream::AesGcmStream(Mode mode, const uint8_t* key, size_t key_len, const uint8_t* nonce,
                            size_t nonce_len)
    : mode_(mode) {
    if (!key || key_len != AesGcm::KEY_LEN) {
        throw PQCException("طول مفتاح AES غير صحيح لبدء البث.");
    }
    if (!nonce || nonce_len != AesGcm::NONCE_LEN) {
        throw PQCException("طول nonce غير صحيح لبدء البث.");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw PQCException("فشل إنشاء سياق AES-GCM للبث: " + openssl_error_string());
    }
    ctx_ = ctx;

    int rc = (mode_ == Mode::Encrypt)
                 ? EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)
                 : EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ctx_ = nullptr;
        throw PQCException("فشل تهيئة خوارزمية AES-256-GCM للبث: " + openssl_error_string());
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce_len), nullptr) !=
        1) {
        EVP_CIPHER_CTX_free(ctx);
        ctx_ = nullptr;
        throw PQCException("فشل ضبط طول IV للبث: " + openssl_error_string());
    }

    rc = (mode_ == Mode::Encrypt) ? EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce)
                                   : EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce);
    if (rc != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ctx_ = nullptr;
        throw PQCException("فشل تهيئة المفتاح والـ IV للبث: " + openssl_error_string());
    }
}

AesGcmStream::~AesGcmStream() {
    if (ctx_) {
        EVP_CIPHER_CTX_free(reinterpret_cast<EVP_CIPHER_CTX*>(ctx_));
        ctx_ = nullptr;
    }
}

size_t AesGcmStream::update(const uint8_t* in, size_t in_len, uint8_t* out) {
    if (in_len == 0) return 0;
    if (!in || !out) {
        throw PQCException("مؤشر بيانات فارغ أثناء البث.");
    }

    auto* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctx_);
    int out_len = 0;
    int rc = (mode_ == Mode::Encrypt)
                 ? EVP_EncryptUpdate(ctx, out, &out_len, in, static_cast<int>(in_len))
                 : EVP_DecryptUpdate(ctx, out, &out_len, in, static_cast<int>(in_len));
    if (rc != 1) {
        throw PQCException("فشل أثناء معالجة دفعة بيانات (streaming update): " +
                            openssl_error_string());
    }
    return static_cast<size_t>(out_len);
}

std::vector<uint8_t> AesGcmStream::finalize_encrypt() {
    if (mode_ != Mode::Encrypt) {
        throw PQCException("finalize_encrypt() استُدعيت على سياق غير مُهيَّأ للتشفير.");
    }
    auto* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctx_);

    uint8_t dummy[16];
    int out_len = 0;
    if (EVP_EncryptFinal_ex(ctx, dummy, &out_len) != 1) {
        throw PQCException("فشل إنهاء عملية التشفير المتدفق: " + openssl_error_string());
    }

    std::vector<uint8_t> tag(AesGcm::TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(AesGcm::TAG_LEN),
                             tag.data()) != 1) {
        throw PQCException("فشل استخراج رمز المصادقة من البث: " + openssl_error_string());
    }
    return tag;
}

void AesGcmStream::finalize_decrypt(const uint8_t* tag, size_t tag_len) {
    if (mode_ != Mode::Decrypt) {
        throw PQCException("finalize_decrypt() استُدعيت على سياق غير مُهيَّأ لفك التشفير.");
    }
    if (!tag || tag_len != AesGcm::TAG_LEN) {
        throw PQCException("طول رمز المصادقة غير صحيح عند إنهاء البث.");
    }

    auto* ctx = reinterpret_cast<EVP_CIPHER_CTX*>(ctx_);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag_len),
                             const_cast<uint8_t*>(tag)) != 1) {
        throw PQCException("فشل ضبط رمز المصادقة قبل التحقق: " + openssl_error_string());
    }

    uint8_t dummy[16];
    int out_len = 0;
    int rc = EVP_DecryptFinal_ex(ctx, dummy, &out_len);
    if (rc <= 0) {
        throw PQCException(
            "فشل التحقق من سلامة البيانات (Authentication Failed) — "
            "الملف تالف أو تم التلاعب به أو المفتاح غير صحيح.");
    }
}

// ==========================================================================
// HybridCipher
//
// صيغة رسائل الذاكرة "PQC1" (encrypt_bytes/decrypt_bytes - رسائل قصيرة):
//   [4B]MAGIC_MSG "PQC1" [2B]طول_اسم_الخوارزمية [N]اسم_الخوارزمية
//   [4B]طول_نص_Kyber [N]نص_Kyber [12B]nonce [16B]tag [4B]طول_البيانات [N]البيانات
//
// صيغة ملفات البث "PQC2" (encrypt_file/decrypt_file - أي حجم):
//   [4B]MAGIC_FILE "PQC2" [2B]طول_اسم_الخوارزمية [N]اسم_الخوارزمية
//   [4B]طول_نص_Kyber [N]نص_Kyber [12B]nonce [8B]طول_البيانات_الأصلية(u64)
//   [...بث...]البيانات المشفرة (بالضبط بنفس طول البيانات الأصلية)
//   [16B]tag  <-- في نهاية الملف، يُتحقق منه بعد معالجة كل البيانات
// ==========================================================================
namespace {

constexpr uint8_t MAGIC_MSG[4] = {'P', 'Q', 'C', '1'};
constexpr uint8_t MAGIC_FILE[4] = {'P', 'Q', 'C', '2'};
constexpr char HKDF_INFO_PREFIX[] = "PQC-Hybrid-AESGCM-v1:";

void append_u16(std::vector<uint8_t>& buf, uint16_t v) {
    buf.push_back(static_cast<uint8_t>(v & 0xFF));
    buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}
uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

void append_u32(std::vector<uint8_t>& buf, uint32_t v) {
    for (int i = 0; i < 4; ++i) buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}
uint32_t read_u32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= (static_cast<uint32_t>(p[i]) << (i * 8));
    return v;
}

void append_u64(std::vector<uint8_t>& buf, uint64_t v) {
    for (int i = 0; i < 8; ++i) buf.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
}
uint64_t read_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (static_cast<uint64_t>(p[i]) << (i * 8));
    return v;
}

}  // namespace

HybridCipher::HybridCipher(const std::string& kyber_algorithm) : kem_(kyber_algorithm) {}

void HybridCipher::generate_keys(const std::string& public_key_path,
                                  const std::string& secret_key_path) const {
    KeyPair kp = kem_.generate_keypair();
    write_file_bytes(public_key_path, kp.public_key.data(), kp.public_key.size());
    write_file_bytes(secret_key_path, kp.secret_key.data(), kp.secret_key.size());

#ifndef _WIN32
    // تقييد صلاحيات المفتاح الخاص لتكون للمالك فقط (قراءة/كتابة)
    if (chmod(secret_key_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        throw PQCException(
            "تم إنشاء المفتاح الخاص لكن فشل ضبط صلاحياته الآمنة على الملف: " + secret_key_path);
    }
#else
    std::cerr << "[تحذير أمني] هذا النظام لا يدعم تقييد صلاحيات الملفات تلقائياً (chmod). "
              << "المفتاح الخاص '" << secret_key_path
              << "' قد يكون قابلاً للقراءة من مستخدمين آخرين على هذا الجهاز — "
              << "قيّد صلاحياته يدوياً.\n";
#endif
}

std::vector<uint8_t> HybridCipher::encrypt_bytes(const std::vector<uint8_t>& plaintext,
                                                   const std::vector<uint8_t>& public_key) const {
    EncapsResult encaps = kem_.encapsulate(public_key);

    auto aes_key =
        hkdf_sha256_derive(encaps.shared_secret.data(), encaps.shared_secret.size(),
                            std::string(HKDF_INFO_PREFIX) + kem_.algorithm_name());

    AesGcm::Sealed sealed =
        AesGcm::encrypt(aes_key.data(), aes_key.size(), plaintext.data(), plaintext.size());
    secure_zero(aes_key.data(), aes_key.size());

    std::vector<uint8_t> out;
    out.insert(out.end(), std::begin(MAGIC_MSG), std::end(MAGIC_MSG));

    const std::string& algo = kem_.algorithm_name();
    if (algo.size() > 0xFFFF) {
        throw PQCException("اسم الخوارزمية طويل جداً.");
    }
    append_u16(out, static_cast<uint16_t>(algo.size()));
    out.insert(out.end(), algo.begin(), algo.end());

    append_u32(out, static_cast<uint32_t>(encaps.ciphertext.size()));
    out.insert(out.end(), encaps.ciphertext.begin(), encaps.ciphertext.end());

    out.insert(out.end(), sealed.nonce.begin(), sealed.nonce.end());
    out.insert(out.end(), sealed.tag.begin(), sealed.tag.end());

    append_u32(out, static_cast<uint32_t>(sealed.ciphertext.size()));
    out.insert(out.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());

    return out;
}

std::vector<uint8_t> HybridCipher::decrypt_bytes(const std::vector<uint8_t>& packed,
                                                   const SecureBuffer& secret_key) const {
    size_t pos = 0;
    auto need = [&](size_t n) {
        if (pos + n > packed.size()) {
            throw PQCException("الرسالة المشفرة تالفة أو غير مكتملة (بيانات ناقصة).");
        }
    };

    need(4);
    if (std::equal(std::begin(MAGIC_FILE), std::end(MAGIC_FILE), packed.begin())) {
        throw PQCException(
            "هذا ملف مشفر (.pqc) وليس رسالة نصية — استخدم أمر decrypt-file بدلاً من decrypt-text.");
    }
    if (!std::equal(std::begin(MAGIC_MSG), std::end(MAGIC_MSG), packed.begin())) {
        throw PQCException("توقيع الرسالة (magic bytes) غير صحيح — ليست رسالة مشفرة بهذا النظام.");
    }
    pos += 4;

    need(2);
    uint16_t algo_len = read_u16(&packed[pos]);
    pos += 2;
    need(algo_len);
    std::string algo(reinterpret_cast<const char*>(&packed[pos]), algo_len);
    pos += algo_len;

    if (algo != kem_.algorithm_name()) {
        throw PQCException("خوارزمية الرسالة ('" + algo + "') لا تطابق الخوارزمية الحالية ('" +
                            kem_.algorithm_name() + "'). أعد المحاولة مع نفس الخوارزمية.");
    }

    need(4);
    uint32_t kem_ct_len = read_u32(&packed[pos]);
    pos += 4;
    need(kem_ct_len);
    std::vector<uint8_t> kem_ciphertext(packed.begin() + pos, packed.begin() + pos + kem_ct_len);
    pos += kem_ct_len;

    need(AesGcm::NONCE_LEN);
    std::vector<uint8_t> nonce(packed.begin() + pos, packed.begin() + pos + AesGcm::NONCE_LEN);
    pos += AesGcm::NONCE_LEN;

    need(AesGcm::TAG_LEN);
    std::vector<uint8_t> tag(packed.begin() + pos, packed.begin() + pos + AesGcm::TAG_LEN);
    pos += AesGcm::TAG_LEN;

    need(4);
    uint32_t ct_len = read_u32(&packed[pos]);
    pos += 4;
    need(ct_len);
    const uint8_t* ct_ptr = &packed[pos];
    pos += ct_len;

    SecureBuffer shared_secret = kem_.decapsulate(kem_ciphertext, secret_key);

    auto aes_key = hkdf_sha256_derive(shared_secret.data(), shared_secret.size(),
                                       std::string(HKDF_INFO_PREFIX) + kem_.algorithm_name());

    std::vector<uint8_t> plaintext =
        AesGcm::decrypt(aes_key.data(), aes_key.size(), nonce.data(), nonce.size(), tag.data(),
                         tag.size(), ct_ptr, ct_len);
    secure_zero(aes_key.data(), aes_key.size());

    return plaintext;
}

void HybridCipher::encrypt_file(const std::string& input_path, const std::string& output_path,
                                 const std::string& public_key_path) const {
    uint64_t plaintext_len = file_size(input_path);
    std::vector<uint8_t> public_key = read_file_bytes(public_key_path);

    EncapsResult encaps = kem_.encapsulate(public_key);
    auto aes_key = hkdf_sha256_derive(encaps.shared_secret.data(), encaps.shared_secret.size(),
                                       std::string(HKDF_INFO_PREFIX) + kem_.algorithm_name());

    std::vector<uint8_t> nonce(AesGcm::NONCE_LEN);
    if (RAND_bytes(nonce.data(), static_cast<int>(AesGcm::NONCE_LEN)) != 1) {
        secure_zero(aes_key.data(), aes_key.size());
        throw PQCException("فشل توليد nonce عشوائي آمن: " + openssl_error_string());
    }

    std::ifstream in_file(input_path, std::ios::binary);
    if (!in_file) {
        secure_zero(aes_key.data(), aes_key.size());
        throw PQCException("تعذر فتح ملف الإدخال: " + input_path);
    }

    std::ofstream out_file(output_path, std::ios::binary | std::ios::trunc);
    if (!out_file) {
        secure_zero(aes_key.data(), aes_key.size());
        throw PQCException("تعذر فتح ملف الإخراج: " + output_path);
    }

    // ---- كتابة الترويسة (Header) ----
    const std::string& algo = kem_.algorithm_name();
    if (algo.size() > 0xFFFF) {
        secure_zero(aes_key.data(), aes_key.size());
        throw PQCException("اسم الخوارزمية طويل جداً.");
    }
    {
        std::vector<uint8_t> header;
        header.insert(header.end(), std::begin(MAGIC_FILE), std::end(MAGIC_FILE));
        append_u16(header, static_cast<uint16_t>(algo.size()));
        header.insert(header.end(), algo.begin(), algo.end());
        append_u32(header, static_cast<uint32_t>(encaps.ciphertext.size()));
        header.insert(header.end(), encaps.ciphertext.begin(), encaps.ciphertext.end());
        header.insert(header.end(), nonce.begin(), nonce.end());
        append_u64(header, plaintext_len);

        if (!out_file.write(reinterpret_cast<const char*>(header.data()),
                             static_cast<std::streamsize>(header.size()))) {
            secure_zero(aes_key.data(), aes_key.size());
            throw PQCException("فشل كتابة ترويسة الملف المشفر.");
        }
    }

    // ---- البث والتشفير على دفعات (لا تحميل للملف كاملاً بالذاكرة) ----
    AesGcmStream stream(AesGcmStream::Mode::Encrypt, aes_key.data(), aes_key.size(), nonce.data(),
                         nonce.size());
    secure_zero(aes_key.data(), aes_key.size());

    std::vector<uint8_t> in_buf(PQC_CHUNK_SIZE);
    std::vector<uint8_t> out_buf(PQC_CHUNK_SIZE);
    uint64_t remaining = plaintext_len;

    while (remaining > 0) {
        size_t to_read = static_cast<size_t>(std::min<uint64_t>(PQC_CHUNK_SIZE, remaining));
        if (!in_file.read(reinterpret_cast<char*>(in_buf.data()),
                           static_cast<std::streamsize>(to_read))) {
            throw PQCException("فشل أثناء قراءة ملف الإدخال (تغيّر الملف أثناء التشفير؟).");
        }
        size_t written = stream.update(in_buf.data(), to_read, out_buf.data());
        if (written > 0 && !out_file.write(reinterpret_cast<const char*>(out_buf.data()),
                                            static_cast<std::streamsize>(written))) {
            throw PQCException("فشل أثناء كتابة البيانات المشفرة.");
        }
        remaining -= to_read;
    }

    std::vector<uint8_t> tag = stream.finalize_encrypt();
    if (!out_file.write(reinterpret_cast<const char*>(tag.data()),
                         static_cast<std::streamsize>(tag.size()))) {
        throw PQCException("فشل كتابة رمز المصادقة (tag) في نهاية الملف.");
    }

    out_file.flush();
    if (!out_file) {
        throw PQCException("فشل حفظ الملف المشفر بشكل كامل (خطأ flush).");
    }
}

void HybridCipher::decrypt_file(const std::string& input_path, const std::string& output_path,
                                 const std::string& secret_key_path) const {
    uint64_t total_size = file_size(input_path);

    std::ifstream in_file(input_path, std::ios::binary);
    if (!in_file) {
        throw PQCException("تعذر فتح ملف الإدخال المشفر: " + input_path);
    }

    auto read_exact = [&](uint8_t* dst, size_t n, const char* what) {
        if (n > 0 &&
            !in_file.read(reinterpret_cast<char*>(dst), static_cast<std::streamsize>(n))) {
            throw PQCException(std::string("الملف تالف أو غير مكتمل عند قراءة: ") + what);
        }
    };

    uint8_t magic_buf[4];
    read_exact(magic_buf, 4, "magic bytes");
    if (std::equal(std::begin(MAGIC_MSG), std::end(MAGIC_MSG), magic_buf)) {
        throw PQCException(
            "هذه رسالة نصية مشفرة (.pqc) وليست ملفاً — استخدم أمر decrypt-text بدلاً من decrypt-file.");
    }
    if (!std::equal(std::begin(MAGIC_FILE), std::end(MAGIC_FILE), magic_buf)) {
        throw PQCException("توقيع الملف غير صحيح — هذا ليس ملفاً مشفراً بهذا النظام.");
    }

    uint8_t len_buf[2];
    read_exact(len_buf, 2, "طول اسم الخوارزمية");
    uint16_t algo_len = read_u16(len_buf);
    std::string algo(algo_len, '\0');
    read_exact(reinterpret_cast<uint8_t*>(algo_len > 0 ? &algo[0] : nullptr), algo_len,
               "اسم الخوارزمية");
    if (algo != kem_.algorithm_name()) {
        throw PQCException("خوارزمية الملف ('" + algo + "') لا تطابق الخوارزمية الحالية ('" +
                            kem_.algorithm_name() + "').");
    }

    uint8_t u32_buf[4];
    read_exact(u32_buf, 4, "طول نص Kyber المشفر");
    uint32_t kem_ct_len = read_u32(u32_buf);
    std::vector<uint8_t> kem_ciphertext(kem_ct_len);
    read_exact(kem_ct_len > 0 ? kem_ciphertext.data() : nullptr, kem_ct_len, "نص Kyber المشفر");

    std::vector<uint8_t> nonce(AesGcm::NONCE_LEN);
    read_exact(nonce.data(), AesGcm::NONCE_LEN, "nonce");

    uint8_t u64_buf[8];
    read_exact(u64_buf, 8, "طول البيانات الأصلية");
    uint64_t plaintext_len = read_u64(u64_buf);

    std::streampos ciphertext_start = in_file.tellg();
    if (ciphertext_start < 0) {
        throw PQCException("تعذر تحديد موضع بداية البيانات المشفرة.");
    }
    uint64_t header_len = static_cast<uint64_t>(ciphertext_start);

    if (header_len + plaintext_len + AesGcm::TAG_LEN != total_size) {
        throw PQCException(
            "حجم الملف لا يطابق ما هو مذكور في الترويسة — الملف تالف أو تم التلاعب به.");
    }

    // قراءة الـ tag من نهاية الملف أولاً (يقع بعد كل البيانات المشفرة)
    std::vector<uint8_t> tag(AesGcm::TAG_LEN);
    in_file.seekg(static_cast<std::streamoff>(header_len + plaintext_len), std::ios::beg);
    read_exact(tag.data(), AesGcm::TAG_LEN, "رمز المصادقة (tag)");

    // العودة لبداية البيانات المشفرة لبدء البث الفعلي
    in_file.seekg(static_cast<std::streamoff>(header_len), std::ios::beg);
    if (!in_file) {
        throw PQCException("فشل إعادة التموضع لبداية البيانات المشفرة.");
    }

    SecureBuffer secret_key = read_file_secure(secret_key_path);
    SecureBuffer shared_secret = kem_.decapsulate(kem_ciphertext, secret_key);

    auto aes_key = hkdf_sha256_derive(shared_secret.data(), shared_secret.size(),
                                       std::string(HKDF_INFO_PREFIX) + kem_.algorithm_name());

    // نكتب لملف مؤقت أولاً؛ لا نستبدل مخرج المستخدم النهائي إلا بعد نجاح
    // التحقق من رمز المصادقة بالكامل — هذا يمنع تسليم بيانات غير موثوقة.
    std::string temp_path = output_path + ".pqc_tmp";
    std::ofstream out_file(temp_path, std::ios::binary | std::ios::trunc);
    if (!out_file) {
        secure_zero(aes_key.data(), aes_key.size());
        throw PQCException("تعذر إنشاء ملف مؤقت للإخراج: " + temp_path);
    }

    AesGcmStream stream(AesGcmStream::Mode::Decrypt, aes_key.data(), aes_key.size(), nonce.data(),
                         nonce.size());
    secure_zero(aes_key.data(), aes_key.size());

    std::vector<uint8_t> in_buf(PQC_CHUNK_SIZE);
    std::vector<uint8_t> out_buf(PQC_CHUNK_SIZE);
    uint64_t remaining = plaintext_len;

    try {
        while (remaining > 0) {
            size_t to_read = static_cast<size_t>(std::min<uint64_t>(PQC_CHUNK_SIZE, remaining));
            if (!in_file.read(reinterpret_cast<char*>(in_buf.data()),
                               static_cast<std::streamsize>(to_read))) {
                throw PQCException("فشل أثناء قراءة البيانات المشفرة.");
            }
            size_t written = stream.update(in_buf.data(), to_read, out_buf.data());
            if (written > 0 && !out_file.write(reinterpret_cast<const char*>(out_buf.data()),
                                                static_cast<std::streamsize>(written))) {
                throw PQCException("فشل أثناء كتابة البيانات المفكوكة إلى الملف المؤقت.");
            }
            remaining -= to_read;
        }

        stream.finalize_decrypt(tag.data(), tag.size());  // يرمي استثناء إذا فشلت المصادقة

        out_file.flush();
        if (!out_file) {
            throw PQCException("فشل حفظ الملف المؤقت بشكل كامل (خطأ flush).");
        }
        out_file.close();
    } catch (...) {
        out_file.close();
        std::remove(temp_path.c_str());  // حذف الملف المؤقت غير الموثوق
        throw;
    }

    if (std::rename(temp_path.c_str(), output_path.c_str()) != 0) {
        std::remove(temp_path.c_str());
        throw PQCException("فشل نقل الملف الناتج إلى المسار النهائي: " + output_path);
    }
}

// ==========================================================================
// أدوات I/O
// ==========================================================================
std::vector<uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw PQCException("تعذر فتح الملف للقراءة: " + path);
    }

    std::streamsize size = file.tellg();
    if (size < 0) {
        throw PQCException("تعذر تحديد حجم الملف: " + path);
    }
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(static_cast<size_t>(size));
    if (size > 0 && !file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw PQCException("فشل في قراءة محتوى الملف بالكامل: " + path);
    }
    return buffer;
}

void write_file_bytes(const std::string& path, const uint8_t* data, size_t len) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw PQCException("تعذر فتح الملف للكتابة: " + path);
    }
    if (len > 0 &&
        !file.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(len))) {
        throw PQCException("فشل في كتابة محتوى الملف: " + path);
    }
    file.flush();
    if (!file) {
        throw PQCException("فشل في حفظ الملف بشكل كامل (خطأ flush): " + path);
    }
}

SecureBuffer read_file_secure(const std::string& path) {
    // نقرأ أولاً إلى متجه عادي (لا يوجد بديل لقراءة I/O)، ثم ننسخ فوراً إلى
    // SecureBuffer ونمسح المتجه المؤقت من الذاكرة قبل أن يُترك لجامع القمامة
    // العادي — لا نترك نسخة من المفتاح السري في ذاكرة غير محمية.
    std::vector<uint8_t> bytes = read_file_bytes(path);
    SecureBuffer buf(bytes.data(), bytes.size());
    secure_zero(bytes.data(), bytes.size());
    return buf;
}

uint64_t file_size(const std::string& path) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        throw PQCException("تعذر فتح الملف لمعرفة حجمه: " + path);
    }
    std::streamoff sz = file.tellg();
    if (sz < 0) {
        throw PQCException("تعذر تحديد حجم الملف: " + path);
    }
    return static_cast<uint64_t>(sz);
}

std::string bytes_to_hex(const uint8_t* data, size_t len) {
    static const char* hex_chars = "0123456789abcdef";
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        result.push_back(hex_chars[(data[i] >> 4) & 0xF]);
        result.push_back(hex_chars[data[i] & 0xF]);
    }
    return result;
}

}  // namespace pqc