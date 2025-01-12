using ShopApi.Models.Database;

namespace ShopApi.Extensions
{
    public static class FileReaderExtensions
    {
        public static List<InitProduct> ReadProductFromCSV(string csvFilePath)
        {
            var result = new List<InitProduct>();
            string[] listOfHeader = null;

            try
            {
                using (var reader = new StreamReader(csvFilePath))
                {
                    string line;
                    if ((line = reader.ReadLine()) != null)
                    {
                        listOfHeader = line.Split('\t');
                    }
                    if (listOfHeader != null && listOfHeader.Length > 0)
                    {
                        while ((line = reader.ReadLine()) != null)
                        {
                            // Rozdzielanie wartości za pomocą tabulatora
                            var values = line.Split('\t');
                            int idIndex = Array.IndexOf(listOfHeader, "code");
                            int nameIndex = Array.IndexOf(listOfHeader, "product_name");
                            int labelsIndex = Array.IndexOf(listOfHeader, "labels");
                            int brandsIndex = Array.IndexOf(listOfHeader, "brands");
                            int quantityIndex = Array.IndexOf(listOfHeader, "quantity");
                            var product = new InitProduct()
                            {
                                Barcode = idIndex != -1 ? (String.IsNullOrEmpty(values[idIndex]) ? "" : values[idIndex]) : "",
                                Name = nameIndex != -1 ? (String.IsNullOrEmpty(values[nameIndex]) ? "" : values[nameIndex]) : "",
                                Label = labelsIndex != -1 ? (String.IsNullOrEmpty(values[labelsIndex]) ? "" : values[labelsIndex]) : "",
                                Capacity = quantityIndex != -1 ? (String.IsNullOrEmpty(values[quantityIndex]) ? "" : values[quantityIndex]) : "",
                                Brand = brandsIndex != -1 ? (String.IsNullOrEmpty(values[brandsIndex]) ? "" : values[brandsIndex]) : "",
                            };
                            if (!String.IsNullOrEmpty(product.Barcode) && product.Barcode.StartsWith("5"))
                                result.Add(product);
                        }
                    }
                }
            } catch(Exception ex)
            {
                throw new Exception(ex.Message);
            }

            return result;
        }
    }
}
