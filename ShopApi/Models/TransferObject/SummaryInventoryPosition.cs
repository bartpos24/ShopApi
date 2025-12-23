namespace ShopApi.Models.TransferObject
{
    public class SummaryInventoryPosition
    {
        public string ProductName { get; set; }
        public double Quantity { get; set; }
        public string Unit { get; set; }
        public double Price { get; set; }
        public DateTime DateOfScanOrModification { get; set; }
    }
}
