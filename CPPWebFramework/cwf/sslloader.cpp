#include "sslloader.h"
#include <QFile>
#include <QDebug>
#include <QSslKey>
#include <QSslCertificate>
#include <QSslConfiguration>
#include <utility>
#include <iostream>
CWF_BEGIN_NAMESPACE

SslLoader::SslLoader(Configuration configuration) : configuration(std::move(configuration))
{
}

QByteArray getFileContent(const QString &fileName, bool &ok)
{
    QFile file(fileName);
    if(file.open(QIODevice::ReadOnly))
    {
        ok = true;
        return file.readAll();
    }
    ok = false;
    qDebug() << "Can't open " << fileName << ": " << file.errorString();
    return QByteArray();
}

QSslConfiguration *buildSslConfiguration(const QSslKey &keySsl,
                                         const QList<QSslCertificate> &certificateChainSsl,
                                         const Configuration &configuration)
{
    auto *temp = new QSslConfiguration;
    temp->setProtocol(configuration.getSslProtocol());
    temp->setPeerVerifyMode(configuration.getSslPeerVerifyMode());
    temp->setPrivateKey(keySsl);
    if (certificateChainSsl.size() > 1) {
        temp->setLocalCertificateChain(certificateChainSsl);
    } else {
        temp->setLocalCertificate(certificateChainSsl.first());
    }
    return temp;
}

QSslConfiguration *SslLoader::getSslConfiguration() const
{
#ifdef QT_NO_SSL
    qDebug() << "Secure Sockets Layer (SSL) is not supported, please check your configuration.";
    return nullptr;
#else
    if(!configuration.getSslKeyFile().isEmpty() && !configuration.getSslCertFile().isEmpty())
    {
        bool okKey, okCert;
        QByteArray myKeyStr(getFileContent(configuration.getSslKeyFile(), okKey));
        QByteArray myCertificateStr(getFileContent(configuration.getSslCertFile(), okCert));

        if(!okKey || !okCert)
        {
            return nullptr;
        }

        QSslKey keySsl(myKeyStr,
                       configuration.getSslKeyAlgorithm(),
                       configuration.getSslEncodingFormat(),
                       configuration.getSslKeyType(),
                       configuration.getSslPassPhrase());

        QSslCertificate certificateSsl(myCertificateStr,
                                       configuration.getSslEncodingFormat());
        QList<QSslCertificate> SslCertificateChain;
        SslCertificateChain.push_back(certificateSsl); // Servercert must be first in Chain

        QList<QString> IntermediateCertificates = configuration.getSslIntermediateCertificateFileNames();

        for (auto const & IntermediateCert : IntermediateCertificates) {
            bool okIntermediate = false;
            auto InterMediateFileData = getFileContent(IntermediateCert,
                                                       okIntermediate);
            std::cout << "Intermediate Okay: " << okIntermediate << "\n";
            QSslCertificate IntermediatecertificateSsl(InterMediateFileData,
                                                       configuration.getSslEncodingFormat());

            std::cout << "Certname " << IntermediateCert.toStdString() << "\n";
            std::cout << "Subject: ";
            for (auto const & SubjectEntries : IntermediatecertificateSsl.subjectInfo(QSslCertificate::SubjectInfo::CommonName)) {
                std::cout << SubjectEntries.toStdString() << "\t";
            }
            std::cout << "\n";
            std::cout << "Issuer: ";
            for (auto const & IssuerEntries : IntermediatecertificateSsl.issuerInfo(QSslCertificate::SubjectInfo::CommonName)) {
                 std::cout << IssuerEntries.toStdString() << "\t";
            }
            std::cout << "\n";
            if (okIntermediate) {
                SslCertificateChain.push_back(IntermediatecertificateSsl);
            }
        }

        if(keySsl.isNull())
        {
            qDebug() << "Invalid SLL key file, please check the CPPWeb.ini file.";
            return nullptr;
        }
        if(certificateSsl.isNull())
        {
            qDebug() << "Invalid SLL cert file, please check the CPPWeb.ini file.";
            return nullptr;
        }

        return buildSslConfiguration(keySsl, SslCertificateChain, configuration);
    }
#endif
    return nullptr;
}

CWF_END_NAMESPACE
