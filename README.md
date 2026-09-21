# PQC Crypto Tool — تشفير هجين مقاوم للحواسيب الكمومية

مكتبة وأداة C++ للتشفير الهجين:
**Kyber / ML-KEM** (عبر `liboqs`) لتبادل المفاتيح بأمان مقاوم للحواسيب الكمومية،
مدموجة مع **HKDF-SHA256** لاشتقاق المفتاح و **AES-256-GCM** لتشفير البيانات الفعلية
(ملفات أو رسائل نصية) بسرعة وبمصادقة تمنع التلاعب.

## المتطلبات
- مترجم C++17 (GCC ≥ 9 أو Clang ≥ 10)
- CMake ≥ 3.16
- OpenSSL (development headers)
- liboqs (Open Quantum Safe) — تُبنى من المصدر

### تثبيت المتطلبات (Debian/Ubuntu)
sudo apt update
sudo apt install -y build-essential cmake ninja-build libssl-dev git

### بناء وتثبيت liboqs (مرة واحدة)
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON
cmake --build liboqs/build --parallel
sudo cmake --install liboqs/build
sudo ldconfig

## بناء المشروع
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

## الاستخدام
./build/pqc_tool keygen alice.pub alice.key
./build/pqc_tool encrypt-file document.pdf document.pdf.pqc alice.pub
./build/pqc_tool decrypt-file document.pdf.pqc document_decrypted.pdf alice.key
./build/pqc_tool encrypt-text "رسالة سرية" message.pqc alice.pub
./build/pqc_tool decrypt-text message.pqc alice.key
./build/pqc_tool info Kyber1024