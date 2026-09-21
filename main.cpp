#include "pqc_crypto.hpp"

#include <iostream>
#include <string>
#include <vector>

namespace {

void print_usage(const char* prog) {
    std::cerr
        << "==========================================================\n"
        << " نظام تشفير مقاوم للحواسيب الكمومية (Post-Quantum Crypto)\n"
        << " Kyber/ML-KEM (liboqs) + HKDF-SHA256 + AES-256-GCM\n"
        << "==========================================================\n\n"
        << "الاستخدام:\n"
        << "  " << prog << " keygen <public_key_out> <secret_key_out> [algorithm=Kyber768]\n"
        << "  " << prog << " encrypt-file <input> <output> <public_key_file> [algorithm]\n"
        << "  " << prog << " decrypt-file <input> <output> <secret_key_file> [algorithm]\n"
        << "  " << prog << " encrypt-text \"<message>\" <output_file> <public_key_file> [algorithm]\n"
        << "  " << prog << " decrypt-text <input_file> <secret_key_file> [algorithm]\n"
        << "  " << prog << " info [algorithm=Kyber768]\n\n"
        << "أمثلة:\n"
        << "  " << prog << " keygen alice.pub alice.key\n"
        << "  " << prog << " encrypt-file secret.pdf secret.pdf.pqc alice.pub\n"
        << "  " << prog << " decrypt-file secret.pdf.pqc secret_decrypted.pdf alice.key\n"
        << "  " << prog << " encrypt-text \"مرحباً بالعالم\" msg.pqc alice.pub\n"
        << "  " << prog << " decrypt-text msg.pqc alice.key\n";
}

int cmd_keygen(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "[!] استخدام ناقص.\n";
        print_usage(argv[0]);
        return 1;
    }
    std::string pub_path = argv[2];
    std::string sk_path = argv[3];
    std::string algo = (argc >= 5) ? argv[4] : "Kyber768";

    pqc::HybridCipher cipher(algo);
    cipher.generate_keys(pub_path, sk_path);

    std::cout << "[+] تم توليد زوج المفاتيح بنجاح باستخدام " << algo << "\n"
              << "    المفتاح العام : " << pub_path << "  (يمكن مشاركته بحرية)\n"
              << "    المفتاح الخاص : " << sk_path << "  (سرّي — لا تشاركه أبداً!)\n";
    return 0;
}

int cmd_encrypt_file(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "[!] استخدام ناقص.\n";
        print_usage(argv[0]);
        return 1;
    }
    std::string in = argv[2], out = argv[3], pub = argv[4];
    std::string algo = (argc >= 6) ? argv[5] : "Kyber768";

    pqc::HybridCipher cipher(algo);
    cipher.encrypt_file(in, out, pub);

    std::cout << "[+] تم تشفير الملف بنجاح: " << in << " -> " << out << "\n";
    return 0;
}

int cmd_decrypt_file(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "[!] استخدام ناقص.\n";
        print_usage(argv[0]);
        return 1;
    }
    std::string in = argv[2], out = argv[3], sk = argv[4];
    std::string algo = (argc >= 6) ? argv[5] : "Kyber768";

    pqc::HybridCipher cipher(algo);
    cipher.decrypt_file(in, out, sk);

    std::cout << "[+] تم فك تشفير الملف بنجاح: " << in << " -> " << out << "\n";
    return 0;
}

int cmd_encrypt_text(int argc, char** argv) {
    if (argc < 5) {
        std::cerr << "[!] استخدام ناقص.\n";
        print_usage(argv[0]);
        return 1;
    }
    std::string message = argv[2];
    std::string out = argv[3], pub = argv[4];
    std::string algo = (argc >= 6) ? argv[5] : "Kyber768";

    pqc::HybridCipher cipher(algo);
    std::vector<uint8_t> pub_key = pqc::read_file_bytes(pub);
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    std::vector<uint8_t> packed = cipher.encrypt_bytes(plaintext, pub_key);
    pqc::write_file_bytes(out, packed.data(), packed.size());

    std::cout << "[+] تم تشفير الرسالة وحفظها في: " << out << "\n";
    return 0;
}

int cmd_decrypt_text(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "[!] استخدام ناقص.\n";
        print_usage(argv[0]);
        return 1;
    }
    std::string in = argv[2], sk_path = argv[3];
    std::string algo = (argc >= 5) ? argv[4] : "Kyber768";

    pqc::HybridCipher cipher(algo);
    std::vector<uint8_t> packed = pqc::read_file_bytes(in);
    pqc::SecureBuffer secret_key = pqc::read_file_secure(sk_path);

    std::vector<uint8_t> plaintext = cipher.decrypt_bytes(packed, secret_key);
    std::string message(plaintext.begin(), plaintext.end());

    std::cout << "[+] الرسالة بعد فك التشفير:\n" << message << "\n";
    return 0;
}

int cmd_info(int argc, char** argv) {
    std::string algo = (argc >= 3) ? argv[2] : "Kyber768";
    pqc::KyberKEM kem(algo);

    std::cout << "الخوارزمية المستخدمة فعلياً : " << kem.algorithm_name() << "\n"
              << "طول المفتاح العام           : " << kem.public_key_length() << " بايت\n"
              << "طول المفتاح الخاص           : " << kem.secret_key_length() << " بايت\n"
              << "طول نص Kyber المشفر (KEM)    : " << kem.ciphertext_length() << " بايت\n"
              << "طول السر المشترك             : " << kem.shared_secret_length() << " بايت\n";
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    std::string command = argv[1];

    try {
        if (command == "keygen") return cmd_keygen(argc, argv);
        if (command == "encrypt-file") return cmd_encrypt_file(argc, argv);
        if (command == "decrypt-file") return cmd_decrypt_file(argc, argv);
        if (command == "encrypt-text") return cmd_encrypt_text(argc, argv);
        if (command == "decrypt-text") return cmd_decrypt_text(argc, argv);
        if (command == "info") return cmd_info(argc, argv);

        std::cerr << "[!] أمر غير معروف: " << command << "\n\n";
        print_usage(argv[0]);
        return 1;
    } catch (const pqc::PQCException& e) {
        std::cerr << "[!] خطأ في التشفير: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "[!] خطأ غير متوقع: " << e.what() << "\n";
        return 3;
    } catch (...) {
        std::cerr << "[!] خطأ غير معروف (unknown exception).\n";
        return 4;
    }
}غير معروف (unknown exception).\n";
        return 4;
    }
}