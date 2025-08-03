## Solution :    
First lets extract the keywords that we have :   
> article, github Arctic Code Vault, Former Microclub member, pokédex
       
Then lets try and google dork it :   

<img width="1069" height="669" alt="image" src="https://github.com/user-attachments/assets/4026cb16-d9a6-420e-812d-ad00d45d05c3" />      

We found an article written by a microclub member talking about the github code vault and if we scroll by we found his pokedex project :    

<img width="855" height="629" alt="image" src="https://github.com/user-attachments/assets/cf1fe835-4c55-4919-9775-feabf21633ef" />       

Our goal of the challenge is to find the 2 pokemons that are in his project, howeve when we click on the link we find that the websits is no longer available, so we must think of a way to go back in time and check out the website.      
And Yes there is a website for that called https://web.archive.org/ ith a way back machine that allows us to visite the website in an old state    
We paste the github url in the wayback machine and find 2 hits :     
<img width="1277" height="402" alt="image" src="https://github.com/user-attachments/assets/3ef156fb-6046-4e86-a558-108affe98383" />        

one in 2023 that is also an unavailable github repo, and one in 2020 around the time the article was written which contains the actual github repo, and  by reading the Readme file we find the link to his web pokedex project which contains the two pokemons :        

<img width="1568" height="358" alt="image" src="https://github.com/user-attachments/assets/5a34eb67-5bb4-43ae-b7bb-c2c54218c3c9" />



> Alakazam and gengar

which is the flag : `ghctf{alakazam_gengar}`




