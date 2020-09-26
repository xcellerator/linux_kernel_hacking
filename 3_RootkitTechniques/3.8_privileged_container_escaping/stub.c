int main(void)
{
	int result;

	result = init_module(example_ko, example_ko_len, args);

	if( result != 0 )
	{
		printf("Error: %d\n", result);
		return(-1);
	}

	return(0);
}
