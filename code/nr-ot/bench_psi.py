import subprocess

#client_set=[0,5,10]
#server_set=[0,5,10]
client_set=[0]
server_set=[0]

if __name__=="__main__":
    for server in server_set: 
        for client in client_set: 
            for i in range(100):
                with open("bench/opus_server_"+str(server)+"_"+str(client), "a")  as server_output: 
                    subprocess.Popen(["build/test/test_psi_nrot_server","127.0.0.1","12345",str(server)], stdout=server_output)
                with open("bench/opus_client_"+str(server)+"_"+str(client), "a") as client_output: 
                    p=subprocess.Popen(["build/test/test_psi_nrot_client","127.0.0.1","12345",str(client)], stdout=client_output)
                    while p.poll() is None: 
                        continue
            print("Done: server size "+str(server)+", client size "+str(client))

