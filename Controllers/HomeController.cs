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

        public string Encrypt([FromBody] RequestModel payload)
        {
            RSAService srv = new RSAService();
            string message = srv.encrypt(payload.Key, payload.Message, true);

            return message;
        }
        public string Decrypt([FromBody] RequestModel payload)
        {
            RSAService srv = new RSAService();
            string message = srv.decrypt(payload.Key, payload.Message, true);

            return message;
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
