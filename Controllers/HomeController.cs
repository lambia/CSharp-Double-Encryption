using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using DoubleEncryption.Models;
using DoubleEncryption.Services;

namespace DoubleEncryption.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public IActionResult Index()
        {
            KeyPair publicKey = new KeyPair() { publicKey = AppStore.publicKeyPem };

            return View(publicKey);
        }

        //[HttpGet]
        //ToDev: aggiungere parametro tipo ClientID o eliminare il metodo?
        //public string GetPublicKey()
        //{
        //    return AppStore.publicKeyPem;
        //}

        [HttpPost]
        public string Download([FromBody] RequestModel payload)
        {
            FileService fs = new FileService();
            AESService aes = new AESService();
            RSAService rsa = new RSAService();

            string key = rsa.Decrypt(payload.Key);
            string vector = rsa.Decrypt(payload.Vector);
            string fileB64 = fs.ReadFile(payload.File);
            byte[] fileBytes = aes.Encrypt(fileB64, key, vector);

            string fileString = Convert.ToBase64String(fileBytes);
            return fileString;
        }

        [HttpPost]
        [DisableRequestSizeLimit]
        public string Upload([FromBody] RequestModel payload)
        {
            FileService fs = new FileService();
            AESService aes = new AESService();
            RSAService rsa = new RSAService();

            string key = rsa.Decrypt(payload.Key);
            string vector = rsa.Decrypt(payload.Vector);
            string fileString = aes.Decrypt(payload.File, key, vector);

            fs.WriteFile(fileString, payload.Message);
            return "200";
            //ToDev: return un http code o un application result
        }
    }
}
