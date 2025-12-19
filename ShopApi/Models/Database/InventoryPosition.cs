namespace ShopApi.Models.Database
{
	public class InventoryPosition
	{
		public int Id { get; set; }
		public double Quantity { get; set; }
		public double Price { get; set; }
		public DateTime ScanDate { get; set; }
		public int ProductId { get; set; }
		public int UserId { get; set; }
        public int InventoryId { get; set; }
		public int? ModifiedByUserId { get; set; }

        public virtual Product? Product { get; set; }
		public virtual User? User { get; set; }
		public virtual User? ModifiedByUser { get; set; }
        public virtual Inventory? Inventory { get; set; }
    }
}
