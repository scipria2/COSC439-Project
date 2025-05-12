#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/usb/ch9.h>
#include <linux/module.h>
#include <linux/scatterlist.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/akcipher.h>
#include <crypto/public_key.h>


//USB device identifiers
#define VENDOR_ID 0x13fe
#define PRODUCT_ID 0x4300

//missing USB interface constants
#define USB_CLASS_MASS_STORAGE 0x08
#define USB_SC_SCSI 0x06
#define USB_PR_BULK 0x50

//Data buffer sizes
#define max_buffer_size 4096
#define rsa_block_size 256
#define max_plain_size (245) //pkcs#1 needs 11 bytes 

//hardcoded public key using rsa (DER format)
static unsigned char public_key[] = {
  0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
  0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00,
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xba, 0xdf, 0x5f,
  0x26, 0x32, 0xd6, 0x29, 0xa6, 0xc9, 0x57, 0xcf, 0x0a, 0xfb, 0x46, 0xe8,
  0xb1, 0xdc, 0x91, 0x08, 0x69, 0x33, 0x1d, 0x2a, 0x16, 0xf7, 0x54, 0xef,
  0x8e, 0xa2, 0x6e, 0x2b, 0x7d, 0xb0, 0x38, 0x20, 0x9e, 0x09, 0x7d, 0xba,
  0xab, 0xa1, 0xa1, 0x4b, 0xcf, 0x67, 0xca, 0xd7, 0x4e, 0x87, 0xaf, 0x6f,
  0xf2, 0x1e, 0xf7, 0x9e, 0xde, 0x0a, 0x47, 0x43, 0xc9, 0x90, 0x35, 0x07,
  0x9e, 0x72, 0x91, 0x5a, 0xc6, 0xe8, 0x90, 0x43, 0x44, 0x6d, 0x98, 0x77,
  0xed, 0xf8, 0x0a, 0x41, 0xe7, 0xf0, 0x5c, 0xa8, 0x94, 0xab, 0x61, 0xa2,
  0xc3, 0x72, 0xc1, 0x3d, 0x27, 0x50, 0xa5, 0x5b, 0xd1, 0x1f, 0x45, 0x8b,
  0x6f, 0x10, 0x4c, 0x8a, 0x0f, 0x4f, 0xac, 0x52, 0x05, 0x25, 0xaa, 0x76,
  0xa6, 0x5d, 0x7b, 0x98, 0xfd, 0x08, 0x6d, 0x1c, 0x48, 0x62, 0xda, 0x3d,
  0x61, 0xe8, 0xe8, 0xe2, 0x6b, 0x79, 0x91, 0x57, 0x40, 0x1b, 0x53, 0xf4,
  0x0f, 0x78, 0xed, 0xa4, 0x4c, 0x40, 0xc5, 0xdb, 0xa0, 0xa3, 0xd7, 0x1f,
  0xc9, 0xcc, 0xd8, 0x74, 0x30, 0xcd, 0xd5, 0x1a, 0x11, 0x0a, 0x16, 0xfd,
  0x06, 0x4b, 0x13, 0xd2, 0x90, 0x7d, 0xb3, 0xcc, 0x4f, 0x3a, 0xd7, 0x92,
  0x51, 0x6d, 0x11, 0x4f, 0x7d, 0x94, 0x08, 0x22, 0xf6, 0xaa, 0x5f, 0xf1,
  0xa9, 0xc9, 0xd0, 0x93, 0x14, 0x51, 0x9c, 0x8c, 0x7e, 0x4a, 0xd0, 0x4c,
  0x22, 0x07, 0x64, 0xd2, 0xae, 0xe6, 0x33, 0x29, 0x14, 0x0d, 0xe8, 0x36,
  0x02, 0x91, 0x09, 0x17, 0x88, 0x28, 0x22, 0xba, 0x4f, 0xd6, 0x50, 0x2a,
  0x20, 0x8a, 0xa9, 0x6d, 0x49, 0x7c, 0x82, 0x75, 0x35, 0x9e, 0x7d, 0x33,
  0xdd, 0xfe, 0xa0, 0xd2, 0xe2, 0xb4, 0x5a, 0xaa, 0xc4, 0xc2, 0x8b, 0xc8,
  0x52, 0x28, 0x37, 0x20, 0xdf, 0x32, 0x22, 0xee, 0xd5, 0x52, 0x82, 0x9a,
  0xf7, 0x02, 0x03, 0x01, 0x00, 0x01
};

//size of the public key
#define public_key_len sizeof(public_key)

// Driver private data structure
struct usb_crypto {
    struct usb_device *udev;
    struct usb_interface *interface;
    unsigned char bulk_in_endpointAddr;
    unsigned char bulk_out_endpointAddr;
    unsigned char buffer[max_buffer_size];
    bool is_encrypting; //bool to determine if driver is encrypting or not
};

//Forward declarations of probe and disconnect
static int usb_crypto_probe(struct usb_interface *interface, const struct usb_device_id *id);
static void usb_crypto_disconnect(struct usb_interface *interface);

// Forward declarations for URB completion handlers
static void usb_crypto_bulk_out_callback(struct urb *urb);
static void usb_crypto_bulk_in_callback(struct urb *urb);


//function prototypes
static int encrypt(unsigned char *data, size_t data_len, unsigned char *out, size_t *out_len);
static int process_data(struct usb_crypto *dev, unsigned char *data, size_t data_len);

static int process_data(struct usb_crypto *dev, unsigned char *data, size_t data_len) 
{
    unsigned char *out_buffer;
    size_t out_len, remaining, chunk_size;
    size_t processed = 0;
    int ret = 0;

    out_buffer = kmalloc(max_buffer_size, GFP_KERNEL);
    if(!out_buffer)
    {
        return -ENOMEM;
    }

    if(dev->is_encrypting)
    {
        // PC to USB aka encrypt
        printk(KERN_INFO "USB Crypto Driver: Encrypting data to the USB Drive\n");

        //process the data
        remaining = data_len;

        while(remaining > 0)
        {
            //determine size of next chunk
            if(remaining > max_plain_size)
            { //process maximum chunk size 
              chunk_size = max_plain_size; 
            }
            else 
            { //process remaining data
                chunk_size = remaining; 
            } 

            out_len = rsa_block_size;
            ret = encrypt(data, chunk_size, out_buffer, &out_len);
            if(ret)
            { // exit if encryption failed
                printk(KERN_ERR "USB Crypto Driver: Encryption failed\n");
                break; 
            }

            //send the encrypted data to the USB device
            ret = usb_bulk_msg(dev->udev,usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
                                out_buffer,
                                out_len,
                                NULL,
                                5000);

            if(ret)
            {
                printk(KERN_ERR "USB Crypto Driver: Failed to send encrypted data to USB device\n");
                break;
            }


            data += chunk_size;
            remaining -= chunk_size;
            processed += out_len; //track total output bytes
        }
    }//end dev->is_encrypting

    kfree(out_buffer);

    if(ret)
        return ret;
    else 
        return processed;

};//end process_data

//encryption with public key
int encrypt(unsigned char *data, size_t data_len, unsigned char *out, size_t *out_len)
{
    //TODO: encryption function
    struct crypto_akcipher *tfm;
    struct akcipher_request *req;
    struct scatterlist src, dst;
    int ret;

    // allocation transform
    tfm = crypto_alloc_akcipher("rsa", 0, 0);

    if(IS_ERR(tfm))
    {
        printk(KERN_ERR "USB Crypto Driver: Failed to allocate akcipher tfm\n");
        return PTR_ERR(tfm);
    }

    //set public key
    ret = crypto_akcipher_set_pub_key(tfm, public_key, public_key_len);
    if (ret)
    {
        printk(KERN_ERR "USB Crypto Driver: Failed to set public key\n");
        crypto_free_akcipher(tfm);
        return ret;
    }
    
    //scatterlist for input and output buffers
    sg_init_one(&src, data, data_len);
    sg_init_one(&dst, out, *out_len);

    //request for encryption
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if(!req)
    {
        printk(KERN_ERR "USB Crypto Driver: Failed to allocate akcipher request\n");
        crypto_free_akcipher(tfm);
        return -ENOMEM;
    }

    akcipher_request_set_crypt(req, &src, &dst, data_len, *out_len);

    //encryption 
    ret = crypto_akcipher_encrypt(req);
    if(ret)
    {
        printk(KERN_ERR "USB Crypto Driver: Data Encryption failed\n");
    } else {
        printk(KERN_INFO "USB Crypto Driver: Data Encryption successful");
    }

    //cleanup
    akcipher_request_free(req);
    crypto_free_akcipher(tfm);

    return ret;
}; //end encrypt()

//Called when the USB device is plugged in and matches this driver
static int usb_crypto_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    struct usb_device *udev = interface_to_usbdev(interface);
    struct usb_host_interface *iface_desc = interface->cur_altsetting;
    struct usb_crypto *dev;
    int i;

    printk(KERN_INFO "USB Crypto Driver: USB Device detected (Vendor: %04x, Product: %04x)\n",
            udev->descriptor.idVendor, udev->descriptor.idProduct);

    
    dev = kzalloc(sizeof(struct usb_crypto), GFP_KERNEL);
    if (!dev) {
        printk(KERN_ERR "USB Crypto Driver: Cannot allocate memory for usb_crypto\n");
        return -ENOMEM;
    }

    dev->udev = usb_get_dev(interface_to_usbdev(interface));
    dev->interface = interface;

    for (i = 0; i < iface_desc->desc.bNumEndpoints; i++) 
    {
        struct usb_endpoint_descriptor *endpoint = &iface_desc->endpoint[i].desc;
            if ((endpoint->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK) == USB_ENDPOINT_XFER_BULK) {
                if (endpoint->bEndpointAddress & USB_DIR_IN) {
                    printk(KERN_INFO "USB Crypto Driver: Bulk IN endpoint found: 0x%X\n", endpoint->bEndpointAddress);
                    dev->bulk_in_endpointAddr = endpoint->bEndpointAddress;
                } else {
                    printk(KERN_INFO "USB Crypto Driver: Bulk OUT endpoint found: 0x%X\n", endpoint->bEndpointAddress);
                    dev->bulk_out_endpointAddr = endpoint->bEndpointAddress;
                }
            }
        }

        //store device data
        usb_set_intfdata(interface, dev);

        if (dev->bulk_in_endpointAddr) 
        {
            struct urb *urb_in = usb_alloc_urb(0, GFP_KERNEL);
            if (urb_in) 
            {
                unsigned char *buf_in = kmalloc(512, GFP_KERNEL);

                if (buf_in) 
                {
                    usb_fill_bulk_urb(urb_in, dev->udev,
                                      usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
                                      buf_in, 512,
                                      usb_crypto_bulk_in_callback, dev);
                    usb_submit_urb(urb_in, GFP_KERNEL);
                } else {
                    usb_free_urb(urb_in);
                }
            }
        }

        if (dev->bulk_out_endpointAddr) {
            struct urb *urb_out = usb_alloc_urb(0, GFP_KERNEL);
            if (urb_out) {
                unsigned char *buf_out = kmalloc(512, GFP_KERNEL);
                if (buf_out) {
                    usb_fill_bulk_urb(urb_out, dev->udev,
                                      usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
                                      buf_out, 512,
                                      usb_crypto_bulk_out_callback, dev);
                    usb_submit_urb(urb_out, GFP_KERNEL);
                } else {
                    usb_free_urb(urb_out);
                }
            }
        }

    return 0;
}//end probe

//called when the USB device is removed
static void usb_crypto_disconnect(struct usb_interface *interface) {
    struct usb_crypto *dev = usb_get_intfdata(interface);

    usb_set_intfdata(interface, NULL);

    if (dev) {
        usb_put_dev(dev->udev);
        kfree(dev);
    }

    printk(KERN_INFO "USB Crypto Driver: USB Device removed\n");
}

// URB completion handler for bulk OUT (data sent to USB device)
static void usb_crypto_bulk_out_callback(struct urb *urb)
{
    struct usb_crypto *dev = urb->context;
    unsigned char *data = urb ->transfer_buffer;
    size_t data_len = urb->actual_length;
    int ret;

    printk(KERN_INFO "USB Crypto Driver: Bulk OUT URB completed\n");

    // allow encryption to happen
    dev->is_encrypting = true;

    ret = process_data(dev, data, data_len);
    if(ret)
    {
        printk(KERN_ERR "USB Crypto Driver: Data Encryption failed\n");
    } else
    {
     printk(KERN_INFO "USB Crypto Driver: Data Encryption successful");   
    }

    // Free the URB
    usb_free_urb(urb);
}

// URB completion handler for bulk IN (data received from USB device)
static void usb_crypto_bulk_in_callback(struct urb *urb)
{
    struct usb_crypto *dev = urb->context;
    
    //allow decryption to happen
    dev->is_encrypting = false;

    // Placeholder for decryption logic after data is received from USB device
    printk(KERN_INFO "USB Crypto Driver: Bulk IN URB completed\n");

    // Free the URB
    usb_free_urb(urb);
}

//match table for supported devices
static struct usb_device_id usb_table[] = 
{
 {USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, USB_PR_BULK)},
 {}
}; 
MODULE_DEVICE_TABLE(usb, usb_table); //end usb_table

//USB driver struct
static struct usb_driver usb_crypto_driver ={
    .name = "USB Crypto Driver",
    .id_table = usb_table,
    .probe = usb_crypto_probe,
    .disconnect = usb_crypto_disconnect,
};

//Module init
static int __init usb_crypto_init(void)
{
    printk(KERN_INFO "USB Crypto Driver: Module loaded\n");
    return usb_register(&usb_crypto_driver);
}

//Module exit
static void __exit usb_crypto_exit(void)
{
    usb_deregister(&usb_crypto_driver);
    printk(KERN_INFO "USB Crypto Driver: Module unloaded\n");
}

module_init(usb_crypto_init);
module_exit(usb_crypto_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stephanie Ciprian and Deep Shah");
MODULE_DESCRIPTION("A USB driver that encrypts and decrypts data in C");
