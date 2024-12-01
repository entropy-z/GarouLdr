SECTIONS
{
	.text ALIGN( 2 ) : SUBALIGN( 2 )
	{
		*( .text$A )
		*( .text$B )
		*( .rdata* )
		*( .data*  )
		*( .text$C )
		*( .text$D )
	}
}