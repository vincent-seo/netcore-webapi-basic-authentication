using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertificateManager;
using CertificateManager.Models;

namespace WebAPI.Security.AsymmetricEncryption
{
    public class CreateRsaCertificates
    {
        public static X509Certificate2 CreateRsaCertificate(CreateCertificates createCertificates, int keySize)
        {
            var basicConstraints = new BasicConstraints
            {
                CertificateAuthority = true,
                HasPathLengthConstraint = true,
                PathLengthConstraint = 2,
                Critical = false
            };

            var subjectAlternativeName = new SubjectAlternativeName
            {
                DnsName = new List<string>
                {
                    "SigningCertificateTest",
                }
            };

            var x509KeyUsageFlags = X509KeyUsageFlags.KeyCertSign
               | X509KeyUsageFlags.DigitalSignature
               | X509KeyUsageFlags.KeyEncipherment
               | X509KeyUsageFlags.CrlSign
               | X509KeyUsageFlags.DataEncipherment
               | X509KeyUsageFlags.NonRepudiation
               | X509KeyUsageFlags.KeyAgreement;

            var enhancedKeyUsages = new OidCollection
            {
                OidLookup.CodeSigning,
                OidLookup.SecureEmail,
                OidLookup.TimeStamping
            };

            var certificate = createCertificates.NewRsaSelfSignedCertificate(
                new DistinguishedName { CommonName = "SigningCertificateTest" },
                basicConstraints,
                new ValidityPeriod
                {
                    ValidFrom = DateTimeOffset.UtcNow,
                    ValidTo = DateTimeOffset.UtcNow.AddYears(1)
                },
                subjectAlternativeName,
                enhancedKeyUsages,
                x509KeyUsageFlags,
                new RsaConfiguration
                {
                    KeySize = keySize,
                    RSASignaturePadding = RSASignaturePadding.Pkcs1,
                    HashAlgorithmName = HashAlgorithmName.SHA256
                });

            return certificate;
        }
    }
}
