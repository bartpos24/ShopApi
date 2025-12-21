namespace ShopApi.Models.Database
{
    public class CommonInventoryPosition
    {
        public int Id { get; set; }
        public string ProductName { get; set; }
        public double Quantity { get; set; }
        public double Price { get; set; }
        public DateTime ScanDate { get; set; }
        public int UserId { get; set; }
        public int InventoryId { get; set; }
        public int? ModifiedByUserId { get; set; }
        public int UnitId { get; set; }

        public virtual ProductUnit? Unit { get; set; }
        public virtual User? User { get; set; }
        public virtual User? ModifiedByUser { get; set; }
        public virtual Inventory? Inventory { get; set; }
    }
}
