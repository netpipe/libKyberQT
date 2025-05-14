#ifndef KYBER_KEM_H
#define KYBER_KEM_H

#include <QString>
#include <QByteArray>
#include <kyber.h>  // Ensure this points to your Kyber implementation
#include "cryptlib.h"
//NAMESPACE_BEGIN(CryptoPP)

class KyberKEM {
public:
    KyberKEM() = default;

    // Generate keypair and return as hex strings
    void generateKeypair(QString& publicKeyHex, QString& secretKeyHex) {
        unsigned char pk[CryptoPP::Kyber512::PUBLICKEYBYTES];
        unsigned char sk[CryptoPP::Kyber512::SECRETKEYBYTES];

        CryptoPP::Kyber512 kyber;
        kyber.KemKeypair(pk, sk);

        publicKeyHex = QByteArray(reinterpret_cast<const char*>(pk), CryptoPP::Kyber512::PUBLICKEYBYTES).toHex();
        secretKeyHex = QByteArray(reinterpret_cast<const char*>(sk), CryptoPP::Kyber512::SECRETKEYBYTES).toHex();
    }

    // Encapsulate: takes public key (hex), returns ciphertext and shared secret as hex
    void encapsulate(const QString& publicKeyHex, QString& ciphertextHex, QString& sharedSecretHex) {
        QByteArray pkBytes = QByteArray::fromHex(publicKeyHex.toUtf8());

        unsigned char ct[CryptoPP::Kyber512::CIPHERTEXTBYTES];
        unsigned char ss[CryptoPP::Kyber512::SHAREDSECRETBYTES];

        CryptoPP::Kyber512 kyber;
        kyber.KemEnc(ct, ss, reinterpret_cast<const unsigned char*>(pkBytes.constData()));

        ciphertextHex = QByteArray(reinterpret_cast<const char*>(ct), CryptoPP::Kyber512::CIPHERTEXTBYTES).toHex();
        sharedSecretHex = QByteArray(reinterpret_cast<const char*>(ss), CryptoPP::Kyber512::SHAREDSECRETBYTES).toHex();
    }

    // Decapsulate: takes secret key and ciphertext (hex), returns shared secret (hex)
    void decapsulate(const QString& secretKeyHex, const QString& ciphertextHex, QString& sharedSecretHex) {
        QByteArray skBytes = QByteArray::fromHex(secretKeyHex.toUtf8());
        QByteArray ctBytes = QByteArray::fromHex(ciphertextHex.toUtf8());

        unsigned char ss[CryptoPP::Kyber512::SHAREDSECRETBYTES];

        CryptoPP::Kyber512 kyber;
        kyber.KemDec(ss,
            reinterpret_cast<const unsigned char*>(ctBytes.constData()),
            reinterpret_cast<const unsigned char*>(skBytes.constData())
        );

        sharedSecretHex = QByteArray(reinterpret_cast<const char*>(ss), CryptoPP::Kyber512::SHAREDSECRETBYTES).toHex();
    }
};

#endif // KYBER_KEM_H
