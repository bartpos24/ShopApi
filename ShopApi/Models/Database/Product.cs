namespace ShopApi.Models.Database
{
    public class Product
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Brand { get; set; }
        public string Capacity { get; set; }
        public string Label { get; set; }
        public bool IsGeneral { get; set; }

        public int UnitId { get; set; }
        public virtual Unit? Unit { get; set; }
        public virtual ICollection<Barcode>? Barcodes { get; set; }

    }
}
