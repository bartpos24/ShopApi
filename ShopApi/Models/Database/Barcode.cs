namespace ShopApi.Models.Database
{
    public class Barcode
    {
        public int Id { get; set; }
        public string Code { get; set; }

        public int ProductId { get; set; }
        public virtual Product? Product { get; set; }
    }
}
