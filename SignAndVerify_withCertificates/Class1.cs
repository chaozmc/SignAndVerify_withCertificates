using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text;
using static SignAndVerify_withCertificates.securityOperations;

namespace SignAndVerify_withCertificates
{
    internal class securityOperations
    {

        public string generateSignatureB64(string messageToSign, X509Certificate2 certificate)
        {
            try
            {
                using (RSA rsa = certificate.GetRSAPrivateKey())
                {
                    return Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(messageToSign), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
                }
            }
            catch (Exception ex)
            {
                throw ex.InnerException;
            }
        }


        public bool verifySignature(string messageToVerify, string b64Signature, X509Certificate2 certificate)
        {
            try
            {
                using (RSA rsa = certificate.GetRSAPublicKey())
                {
                    return rsa.VerifyData(Encoding.UTF8.GetBytes(messageToVerify), Convert.FromBase64String(b64Signature), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                }
            }
            catch (Exception ex)
            {

                throw ex.InnerException;
            }
           
            
        }



            public byte[] GetCertificateFromLocalMachineStore(string friendlyName)
            {
                var store = GetLocalMachineCertificates();
                X509Certificate2 certificate = null;
                foreach (var cert in store.Cast<X509Certificate2>().Where(cert => cert.FriendlyName.Equals(friendlyName)))
                {
                    certificate = cert;
                }
                return certificate != null ? certificate.Export(X509ContentType.Pkcs12) : null;
            }

            private static X509Certificate2Collection GetLocalMachineCertificates()
            {
                var localMachineStore = new X509Store(StoreLocation.LocalMachine);
                localMachineStore.Open(OpenFlags.ReadOnly);
                var certificates = localMachineStore.Certificates;
                localMachineStore.Close();
                return certificates;
            }

    }
}
