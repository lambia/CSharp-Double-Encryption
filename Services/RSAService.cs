using System;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Text;
//using System.Collections.Generic;
//using System.Linq;
//using System.Threading.Tasks;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
//using Org.BouncyCastle.Crypto;
//using Org.BouncyCastle.Asn1.Pkcs;
//using Org.BouncyCastle.OpenSsl;
//using Org.BouncyCastle.Pkcs;

namespace DoubleEncryption.Services
{
    public class RSAService
    {
        public string Decrypt(string text)
        {
            var strOutput = "";
            var stringParts = Regex.Split(text, AppStore._gsRegex);

            for (int i = 0; i < stringParts.Length; i++)
            {
                string stringPart = stringParts[i];
                if (stringPart != "")
                {
                    string buffer = DecryptChunk(stringPart);
                    strOutput += buffer;
                }
            }

            return strOutput;
        }

        public string DecryptChunk(string encB64)
        {
            byte[] encBytes = Convert.FromBase64String(encB64);

            //Paddding aggiuntivo per javascript se i block size non fossero corretti
            if (encBytes.Length < AppStore._blockSize)
            {
                encBytes = PadByteArray(encBytes, (byte)0x00, AppStore._blockSize);
            }

            // Create an array to store the decrypted data in it
            byte[] decBytes = AppStore.rsa.Decrypt(encBytes, false);

            // Get the string value from the decryptedData byte array
            UTF8Encoding byteConverter = new UTF8Encoding();
            string decB64 = byteConverter.GetString(decBytes);

            return decB64;
        }

        public byte[] PadByteArray(byte[] byteArray, byte newByte, int newLength)
        {
            byte[] result = new byte[newLength];
            int oldLength = byteArray.Length;
            int newBytesNumber = newLength - oldLength;

            byteArray.CopyTo(result, newBytesNumber);

            for (int i = 0; i < newBytesNumber; i++)
            {
                result[i] = (byte)newByte;
            }

            return result;
        }

        public static string PublicXML2PEM(RSACryptoServiceProvider rsa)
        {
            RsaKeyParameters publicKey = DotNetUtilities.GetRsaPublicKey(rsa);

            if (publicKey != null) // if XML RSA key contains public key
            {
                SubjectPublicKeyInfo publicKeyInfo =
                    SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
                return FormatPem(publicKeyInfo.GetEncoded(), "PUBLIC KEY");
            }

            return null;
        }

        private static string FormatPem(byte[] pemBytes, string keyType)
        {
            string pem = Convert.ToBase64String(pemBytes);
            var sb = new StringBuilder();
            sb.AppendFormat("-----BEGIN {0}-----\n", keyType);

            int line = 1, width = 64;

            while ((line - 1) * width < pem.Length)
            {
                int startIndex = (line - 1) * width;
                int len = line * width > pem.Length
                              ? pem.Length - startIndex
                              : width;
                sb.AppendFormat("{0}\n", pem.Substring(startIndex, len));
                line++;
            }

            sb.AppendFormat("-----END {0}-----\n", keyType);
            return sb.ToString();
        }
    }
}
