typedef struct{
  uint32_t idx;  
  public_key E;  
} Request __attribute__((packed)); 

typedef struct{
  public_key E[2];  
} Response __attribute__((packed)); 
//typedef struct{
//  uint32_t idx; 
//  public_key E[2];  
//} Response __attribute__((packed)); 

typedef struct{
  large_private_key lpk;
  size_t ssid; //session ID 
} Finalization __attribute((packed));
