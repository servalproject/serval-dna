struct fifo 	*fifo_alloc(unsigned int size);
void		fifo_free(struct fifo *fifo);
void		fifo_reset(struct fifo *fifo);
unsigned int	fifo_put(struct fifo *fifo, uint8_t *buffer, unsigned int len);
unsigned int	fifo_get(struct fifo *fifo, uint8_t *buffer, unsigned int len);
unsigned int	fifo_unget(struct fifo *fifo, uint8_t *buffer, unsigned int len);
unsigned int	fifo_avail(struct fifo *fifo);
unsigned int	fifo_space(struct fifo *fifo);





