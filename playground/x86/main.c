


void test()
{
    int var1 = 2010;
    int var2 = 10;
    int var3 = 0;

    var3 = var1 + var2;
    var3 = var1 - var2;
    var3 = var1 * var2;
    var3 = var1 / var2;

    if (var3 > var2)
    {
        var2 = var3;
    }
}


int main()
{
	test();
  return 0;
}
