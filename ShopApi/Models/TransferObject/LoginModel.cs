using ShopApi.Models.Enums;

namespace ShopApi.Models.TransferObject
{
    public class LoginModel
    {
        public string Username { get; set; }
        public string Passowrd { get; set; }
        public string? SSAID { get; set; }
        public ELoginType LoginType { get; set; }
    }
}
