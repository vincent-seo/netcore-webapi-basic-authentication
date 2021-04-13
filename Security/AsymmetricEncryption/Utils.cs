using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace WebAPI.Security.AsymmetricEncryption
{
    public static class Utils
    {
        public static RSA CreateRsaPublicKey(X509Certificate2 certificate)
        {
            RSA publicKeyProvider = certificate.GetRSAPublicKey();
            return publicKeyProvider;
        }

        public static RSA CreateRsaPrivateKey(X509Certificate2 certificate)
        {
            RSA privateKeyProvider = certificate.GetRSAPrivateKey();
            return privateKeyProvider;
        }
    }
}
