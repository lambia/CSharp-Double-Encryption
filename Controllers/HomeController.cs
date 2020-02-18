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

        public IActionResult Index()
        {
            RSAService srv = new RSAService();
            RSAKeyPair chiavi = srv.handshake();

            return View(chiavi);
        }

        //Client genera chiavi. Server cifra con la pub del client e risponde. Client decifra con propria private.
        [HttpPost]
        public string Download([FromBody] RequestModel payload)
        {
            //ToDo #1: prendere file da FS e cifrarlo
            RSAService srv = new RSAService();
            string message = srv.EncryptLongText(payload.Key, payload.Message, true);

            return message;
        }

        //Server genera chiavi e invia pub. Client uploada. Server decifra con propria private.
        [HttpPost]
        public string Upload([FromBody] RequestModel payload)
        {
            //ToDo #2: tenere in canna le private key nell'istanza
            RSAService srv = new RSAService();
            string message = srv.DecryptLongText(payload.Key, payload.Message, false);

            return message;
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
