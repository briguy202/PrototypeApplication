using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data.Entity;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrototypeApplication.EntityFrameworkConsole
{
	class Program
	{
		static void Main(string[] args)
		{
			//Database.SetInitializer(new DropCreateDatabaseIfModelChanges<Context>());
			Database.SetInitializer(new DropCreateDatabaseIfModelChanges<Context>());
			var context = new Context();

			//var entity = new MyEntity { Name = "Foo" };
			//context.MyEntities.Add(entity);

			var entity = context.MyEntities.Find(1);
			if (entity == null)
				entity = new MyEntity();
			entity.Description = "My Description";
			entity.RelatedItems = new List<RelatedData>
			{
				new RelatedData() {
					RelatedValue = "Foo"
				}
			};

			context.SaveChanges();
		}
	}

	[Table("BrianaEntity")]
	public class MyEntity
	{
		[Key]
		public int MyKey { get; set; }
		public string Name { get; set; }
		[Required]
		public string Description { get; set; }
		public List<RelatedData> RelatedItems { get; set; }
	}

	[Table("RelatedData")]

	public class RelatedData
	{
		public int Id { get; set; }
		public string RelatedValue { get; set; }
	}

	public class Context : DbContext
	{
		public DbSet<MyEntity> MyEntities { get; set; }
		public DbSet<RelatedData> RelatedData { get; set; }
	}
}
