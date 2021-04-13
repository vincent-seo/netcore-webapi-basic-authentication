using System;
using System.Text;
using System.Threading.Tasks;
using CertificateManager;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.VisualBasic.CompilerServices;
using WebAPI.Security.AsymmetricEncryption;
using WebAPI.Security.SymetricEncryption;
using Utils = WebAPI.Security.AsymmetricEncryption.Utils;

namespace WebAPI
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class ApiKeyAuthAttribute : Attribute, IAsyncActionFilter
    {
        private const string ApiKeyHeaderName = "ApiKey";

        public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
        {
            if (!context.HttpContext.Request.Headers.TryGetValue(ApiKeyHeaderName, out var potentialApiKey))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            var apiKey = "abc";

            if (!apiKey.Equals(potentialApiKey))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            ASymmetricTest();

            await next();
        }

        public void SymmetricTest()
        {
            var text = "I have a big dog. You've got a cat. We all love animals!";


            Console.Out.WriteLine("-- Encrypt Decrypt symmetric --");
            Console.Out.WriteLine("");

            var symmetricEncryptDecrypt = new SymmetricEncryption();
            var (Key, IVBase64) = symmetricEncryptDecrypt.InitSymmetricEncryption();

            var encryptedText = symmetricEncryptDecrypt.Encrypt(text, IVBase64, Key);

            Console.WriteLine("-- Key --");
            Console.WriteLine(Key);
            Console.WriteLine("-- IVBase64 --");
            Console.WriteLine(IVBase64);

            Console.WriteLine("");
            Console.WriteLine("-- Encrypted Text --");
            Console.WriteLine(encryptedText);

            var decryptedText = symmetricEncryptDecrypt.Decrypt(encryptedText, IVBase64, Key);

            Console.WriteLine("-- Decrypted Text --");
            Console.WriteLine(decryptedText);
        }

        public void ASymmetricTest()
        {
            Console.WriteLine("Hello World!");
            var serviceProvider = new ServiceCollection()
                .AddCertificateManager()
                .BuildServiceProvider();

            var cc = serviceProvider.GetService<CreateCertificates>();

            var cert3072 = CreateRsaCertificates.CreateRsaCertificate(cc, 3072);
            var publicKey = Utils.CreateRsaPublicKey(cert3072);
            var privateKey = Utils.CreateRsaPrivateKey(cert3072);

            var text = "I have a big dog. You've got a cat. We all love animals!";

            Console.WriteLine("-- Encrypt Decrypt asymmetric --");

            var asymmetricEncryptDecrypt = new AsymmetricEncryption();
            var encryptedText = asymmetricEncryptDecrypt.Encrypt(text, publicKey);

            Console.WriteLine("");
            Console.WriteLine("-- Encrypted Text --");
            Console.WriteLine(encryptedText);

            var decryptedText = asymmetricEncryptDecrypt.Decrypt(encryptedText, privateKey);

            Console.WriteLine("-- Decrypted Text --");
            Console.WriteLine(decryptedText);
        }
    }
}
