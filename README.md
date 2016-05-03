
This is a work-in-progress, experimental Python 3 implementation of aDTN, a network layer protocol for anonymous wireless delay-tolerant networking.

On top of it is a simple mechanism to flood messages all over the network. It can be viewed as a propaganda-spreading automated system that hides the source of the content.

Planned are further services that run on top of aDTN, such as a more controlled way to exchange data of all kinds, not just messages. One could implement an anonymous publish-subscribe system or an anonymous file-sharing network on near-by devices without any need for infrastructure such as an Internet connection or wireless access points.


## If you want to test/run it...

This application broadcasts aDTN packets inside Ethernet frames over the wireless medium. To allow that, you first must set your wireless card to IBSS mode (also known as ad-hoc mode). This means it will not connect to an access point, so you will be disconnected from the Internet (*gasp*!) but you will be able to directly exchange data with other devices running aDTN wherever you are. Then set the ESSID to `aDTN` and choose a channel. It is important that everyone on the same network agrees on a channel, so I suggest you choose channel 1 (2432MHz) unless your community decides otherwise.

On a Linux system, you need to disable your network manager, wpa_supplicant and the like. Then execute the following as root, replacing `<iface>` with your wireless interface name:

    iw dev <iface> set type ibss
    ip l s up <iface>
    iw <iface> ibss join aDTN 2432

Some wireless cards seem to reset the ESSID after the laptop has been suspended, so make sure that it is still set to `aDTN` afterwards. If not, run the last command again.

### Creating keys

Before you can use aDTN you need to set up encryption keys. They are used to enforce that you can only exchange data with your "friends" (i.e. people you trust) and to anonymize your traffic. If you do not have any keys you are not able to receive nor send any messages, because aDTN is a friend-to-friend protocol.

Go to the directory with the code and run:

    python3 key_manager.py -c <filename>

Replace `<filename>` with something you can remember. This will create one key and place it in the data/keys/ directory, with the name `<key_name>.key`. Then share the key with a friend - they should store it in the same directory and use the same network configuration (ESSID, channel) to be able to exchange messages with you.


### Sending messages

To send a message run:

    python3 message_store.py -c "<message>"

Replace `<message>` with whatever text you want to send. Make sure to use quotation marks. Note: the message may not be sent right away.

The payload of an aDTN packet is limited to 1460 bytes, so do not write a novel. But it will be able to fit up to the size of 10 tweets if your encoding uses 1 byte per character; worst case scenario a bit more than 2 tweets.

### Displaying messages

To show all the messages in your message store (both all sent and received messages) run:

    python3 message_store.py -a

This will list the ID of each message followed by the message itself.

### Deleting messages

If you want to delete a message - and prevent your device from spreading it further in the network - do:

    python3 message_store.py -d <ID>

You can obtain the message ID when listing all the messages contained in the message store.


## DANGER! Here be dragons!
The keys are used to encrypt traffic between you and your friends. They ensure you only exchange data with people you have shared a key with and anonymize your traffic.

These are symmetric keys, so don't go around sharing them with people you do not trust. If you only know public key cryptography (i.e. what you use for encrypting and signing emails), this is like sharing both your public and your private key in one go. You do not want that.

Also do not share a key you received from a friend or friends with other people. It's a secret shared only between you and that group of people, so do not show it to anyone else without the permission of the group.

While it's more secure to use public key cryptography due to the danger of a member leaking a key, having a shared key per trust group instead of a public key per trusted individual can improve performance significantly. However, things are not set in stone yet and in general I prefer higher security, so this may change in the future. Especially since device performance is always increasing and we might also have high bandwidth ad-hoc wireless soon.


