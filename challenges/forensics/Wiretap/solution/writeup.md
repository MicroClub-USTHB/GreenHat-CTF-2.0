# Wiretap

## **Challenge Overview**

The challenge involved analyzing a Bluetooth network capture (`.pcap`) file to extract an embedded flag hidden within an audio stream. The captured data contained HCI-VT & HCI-CMD ,SBC (Subband Codec) encoded audio packets, transmitted over the A2DP (Advanced Audio Distribution Profile) protocol.

# notes i got from some search:

Bluetooth is an extremely contrived communications protocol. It has its own physical and link layers, and its own transports. To avoid going into too much detail here - we will describe the main elements you need to know to understand the solution to this challenge.

1. **HCI** - HCI stands for host controller interface, and is in fact an internal communications bus that connects the host to the Bluetooth controller. HCI isn't actually broadcasted and carries no relevant information in this context.
2. **ACL** - ACL stands for Asynchronous connection-oriented logical transport. To make things easier - we can think of it as a datagram based communication protocol, much like UDP.
3. **SCO** - SCO stands for Synchronous Connection Oriented Link, and is a more reliable, symmetric link. Broadly generalized - if ACL is like UDP - SCO is like TCP.
4. **L2CAP** - L2CAP stands for Logical Link Control Adaptation Protocol and is the protocol which actually carries data in this capture. You can also see this by looking at the protocol hierarchy - where the majority of content (Percent Bytes) can be seen to be contained within that layer

### SBC

SBC stands for low-complexity subband codec - and it is indeed a very simple codec designed for freely-licensed Bluetooth audio applications. So it seems our goal is to extract the audio from this capture, and listen to it. This is easier said than done, since there does not seem to be any information whatsoever on how to do this online. Wireshark does not offer any option to extract the audio, and it's not quite clear what its format is.

## **Step 1: Analyzing the PCAP File**

To start, I opened the `.pcap` file in **Wireshark** to inspect the captured Bluetooth traffic. Using  **"Statistics → Protocol Hierarchy"** , I noticed that the **btl2cap** (Bluetooth L2CAP) protocol had a significant amount of data compared to other protocols. This indicated that the challenge might involve an audio transmission.

Next, I applied a **Wireshark display filter** to focus on SBC packets:

```
sbc
```

This filter isolated the **A2DP (Advanced Audio Distribution Profile)** stream, revealing **SBC-encoded audio data** within the packet payloads.

## **Step 2: Extracting Raw SBC Data**

To extract the SBC packets efficiently, I used  **tshark** , the command-line version of Wireshark. The goal was to **filter the correct connection ID** and **export the raw data to JSON** format:

```
tshark -r  challenge.pcapng -d "sbc" -T json -x > data.json

```

This command:

* Reads the `challenge.pcapng` file.
* Decodes L2CAP packets associated with A2DP (SBC codec).
* Exports data in **JSON format** while ensuring raw hexadecimal output (`-x` flag).

## **Step 3: Processing SBC Frames in Python**

With the extracted JSON file (`data.json`), I used **Python** to parse the data and extract the raw SBC frames, while omitting the **1-byte header** present in each packet.

> the script can be found in the test.ipynb file This script:

* Loads the `data.json` file.
* Extracts the **SBC raw payload** from each packet.
* Removes the  **1-byte packet header** .
* Writes the cleaned SBC data to `output.sbc`.

## **Step 4: Converting SBC to WAV**

Now that we had the extracted SBC audio, we needed to  **convert it to a standard audio format (WAV)** . The easiest way to do this was using `ffmpeg`:

```
ffmpeg -i  output.sbc flag.wav
```

This converted the **SBC-encoded audio** into a playable `flag.wav` file.

## **Step 5: Recovering the Flag**

Finally, I played the `flag.wav` file, which revealed the song , now by just listening to it , its easier to identify the song and the singer!

```
flag : ghctf{birds_of_a_feather}
```

---
