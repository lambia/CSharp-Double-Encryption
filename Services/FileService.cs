using System;
using System.IO;

namespace RSAWebApp.Services
{
    public class FileService
    {

        public void WriteFile(string fileString, string fileName)
        {
            byte[] decryptedBinary = Convert.FromBase64String(fileString);
            File.WriteAllBytes(AppStore._path + fileName, decryptedBinary);
        }
        public string ReadFile(string fileName)
        {
            byte[] file = File.ReadAllBytes(AppStore._path + fileName);
            string fileB64 = Convert.ToBase64String(file);
            return fileB64;
        }

    }
}
