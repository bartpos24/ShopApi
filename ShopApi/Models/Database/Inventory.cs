namespace ShopApi.Models.Database
{
    public class Inventory
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Type { get; set; }
        public string ExecuteWay { get; set; }
        public string ResponsiblePersonName { get; set; }
        public string CompanyName { get; set; }
        public string CompanyAddress { get; set; }
        public string ComissionTeam { get; set; }
        public string PersonToValue { get; set; }
        public string PersonToCheck { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public int CreatedByUserId { get; set; }
        public int InventoryStatusId { get; set; }

        public virtual User CreatedByUser { get; set; }
        public virtual InventoryStatus InventoryStatus { get; set; }
    }
}
