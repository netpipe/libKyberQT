#include <QDebug>
#include "libkyber.h"

int main() {

KyberKEM kem;
QString pk, sk, ct, ss1, ss2;

kem.generateKeypair(pk, sk);
kem.encapsulate(pk, ct, ss1);
kem.decapsulate(sk, ct, ss2);

qDebug() << "Public Key:" << pk;
qDebug() << "Secret Key:" << sk;
qDebug() << "Ciphertext:" << ct;
qDebug() << "Shared Secret A (from encaps):" << ss1;
qDebug() << "Shared Secret B (from decaps):" << ss2;

}
