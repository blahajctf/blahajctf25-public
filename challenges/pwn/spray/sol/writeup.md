Intended solve path: cross-cache attack. modify msg_msg headers through UAF write/read to get OOB read in kmalloc-cg-1k cache. leak pipe_buf ptr and it's page. arb free the page through msg_msg. spray skbuffs on top of the pipe_buf obj to modify pipe_buf struct. from here, you can do kROP (although im not sure if the required gadgets will be there) or elevate it to a page UAF by modifying LSB of page pointer so you have 2 pipe bufs referencing the same page. If you do the second method, priv esc can be obtained through setuid+fork spray  

Other solve paths: honestly there could be a lot hence the chal flag being `all roads lead to rome` 

Potential issues: Reliability of exploit is not high so player might have to keep running his/her exploit script (many times) till root shell is obtained. sometimes sprays done is not enough 
