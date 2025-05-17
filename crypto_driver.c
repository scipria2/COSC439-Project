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
#include <linux/fs.h>
#include <linux/uaccess.h>


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

//hardcoded public key using rsa (DER format)
static const unsigned char public_key[] = {
  0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa5, 0xb0, 0x8a,
  0x2f, 0x87, 0xe1, 0x85, 0x4f, 0x51, 0x79, 0xe7, 0x52, 0x4b, 0xdf, 0x4e,
  0x41, 0xef, 0xc7, 0x9f, 0x68, 0x72, 0x70, 0xa1, 0x00, 0x19, 0x22, 0x57,
  0xd5, 0x1b, 0xc2, 0x9c, 0x5b, 0x76, 0x05, 0xb6, 0x93, 0x2c, 0x2d, 0xaf,
  0xad, 0xb3, 0x95, 0x3b, 0xd8, 0x22, 0xf6, 0x4a, 0xdf, 0xc1, 0x4a, 0x6a,
  0x6f, 0x87, 0x2b, 0xce, 0x96, 0xe5, 0xc0, 0x3d, 0x5b, 0x3b, 0x87, 0xb0,
  0x03, 0xb7, 0x7f, 0xb3, 0xd7, 0x13, 0x65, 0x43, 0xb0, 0xdc, 0xe8, 0xf5,
  0x65, 0x37, 0x0e, 0xbb, 0x73, 0x51, 0xc9, 0x4c, 0x42, 0x3e, 0xa1, 0xe9,
  0x05, 0xc3, 0x29, 0x9b, 0xf4, 0xdc, 0xc3, 0xdb, 0xd8, 0x63, 0x9e, 0xed,
  0x74, 0xcd, 0xe8, 0x08, 0x52, 0x7b, 0x12, 0xdc, 0x3e, 0xb6, 0x9a, 0x55,
  0x66, 0xdb, 0x7e, 0xd4, 0xf7, 0x13, 0xa3, 0x94, 0x83, 0x75, 0x34, 0x5e,
  0x5f, 0x32, 0x6c, 0x99, 0x6e, 0x61, 0x6f, 0x01, 0xcf, 0x2f, 0xb3, 0x23,
  0x33, 0x0c, 0xa0, 0xdc, 0xad, 0x59, 0xc3, 0x70, 0xfb, 0xf1, 0x38, 0x62,
  0xfe, 0xf8, 0x7a, 0x2a, 0x22, 0x01, 0x64, 0x32, 0xb9, 0xf5, 0x0c, 0x64,
  0x99, 0x0f, 0x06, 0x57, 0x65, 0x78, 0xaa, 0xd0, 0xd1, 0x68, 0x14, 0xe4,
  0xb6, 0x12, 0x6d, 0xed, 0xed, 0xbc, 0xcf, 0x80, 0x64, 0x40, 0xdd, 0x96,
  0x11, 0x43, 0x15, 0xe6, 0x06, 0xf0, 0x00, 0x75, 0x4e, 0x67, 0xf2, 0x9e,
  0xd6, 0xa6, 0xa7, 0xbc, 0x81, 0x3a, 0xf7, 0xf4, 0x3a, 0x10, 0x48, 0x1f,
  0x0e, 0x3f, 0x61, 0x4b, 0x5c, 0x8a, 0xd4, 0xc2, 0x8a, 0xa3, 0xfa, 0x92,
  0xfe, 0x8f, 0xdb, 0x70, 0xf5, 0x3b, 0x66, 0x3b, 0x33, 0x4b, 0x30, 0x3d,
  0x3c, 0x67, 0x07, 0x07, 0x6d, 0xca, 0x5d, 0xcb, 0xb9, 0x9a, 0xe1, 0xa3,
  0x25, 0x59, 0xe8, 0xbe, 0x74, 0x96, 0xfe, 0xea, 0x42, 0x42, 0xd8, 0xfe,
  0xf7, 0x02, 0x03, 0x01, 0x00, 0x01
};

//size of the public key
#define public_key_len sizeof(public_key)

static struct crypto_akcipher *tfm = NULL;

// Driver private data structure
struct usb_crypto {
    struct usb_device *udev;
    struct usb_interface *interface;
    unsigned char bulk_in_endpointAddr;
    unsigned char bulk_out_endpointAddr;
    unsigned char buffer[max_buffer_size];
    //bool is_encrypting; //bool to determine if driver is encrypting or not
};



//Forward declarations of probe and disconnect
static int usb_crypto_probe(struct usb_interface *interface, const struct usb_device_id *id);
static void usb_crypto_disconnect(struct usb_interface *interface);

// Forward declarations for URB completion handlers
static void usb_crypto_bulk_out_callback(struct urb *urb);
static void usb_crypto_bulk_in_callback(struct urb *urb);

//function prototypes
int set_public_key(void);
static int encrypt_data(struct crypto_akcipher *tfm, unsigned char *data, unsigned int data_len, unsigned char *out, unsigned int *out_len);

//set the public key
int set_public_key(void)
{
    tfm = crypto_alloc_akcipher("rsa", 0, 0);
    if(IS_ERR(tfm))
    {
        printk(KERN_ERR "USB Crypto Driver: Failed to allocate akcipher tfm\n");
        return PTR_ERR(tfm);
    }

    int ret = crypto_akcipher_set_pub_key(tfm, public_key, public_key_len);
    if (ret)
    {
        printk(KERN_ERR "USB Crypto Driver: Failed to set public key: %d\n", ret);
        crypto_free_akcipher(tfm);
        return ret;
    }
    else {
        printk(KERN_INFO "USB Crypto Driver: Public key set successfully\n");
    }
        
    return ret;
};

//encryption with public key
int encrypt_data(struct crypto_akcipher *tfm, unsigned char *data, unsigned int data_len, unsigned char *out, unsigned int *out_len)
{
    struct akcipher_request *req;
    struct scatterlist src, dst;
    int ret;
    
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
    } else 
    {
        *out_len = req->dst_len;
        printk(KERN_INFO "USB Crypto Driver: Data Encryption successful");
    }

    //cleanup
    akcipher_request_free(req);

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

        /*
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
        */

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

    unsigned char *encrypted_data = kmalloc(512, GFP_KERNEL);
    unsigned int encrypted_data_len = 512;

    printk(KERN_INFO "USB Crypto Driver: Intercepted OUT URB\n");

    ret = encrypt_data(tfm, data, data_len, encrypted_data, &encrypted_data_len);
    if(ret)
    {
        printk(KERN_ERR "USB Crypto Driver: Encryption failed from bulk OUT: %d\n.", ret);
        kfree(encrypted_data);
        return;
    }
    else 
    {
        printk(KERN_INFO "USB Crypto Driver: Encryption successful from bulk OUT\n");
    }

    //create a new URB with encrypted data
    struct urb *encrypted_urb = usb_alloc_urb(0, GFP_KERNEL);
    if(!encrypted_urb)
    {
        printk(KERN_ERR "USB Crypto Driver: Failed to create encrypted URB: %d\n", ret);
    }
    else 
    {
        printk(KERN_INFO "USB Crypto Driver: Successfully created encrypted URB\n");
    }

    usb_fill_bulk_urb(encrypted_urb, dev->udev,
                        usb_rcvbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
                        encrypted_data, encrypted_data_len,
                        usb_crypto_bulk_out_callback, dev);
    
    
    //submit encrypted data URB
    ret = usb_submit_urb(encrypted_urb, GFP_KERNEL);
    if(ret)
    {
        printk(KERN_ERR "USB Crypto Driver: Failed to submit encrypted URB: %d\n", ret);
        usb_free_urb(encrypted_urb);
        kfree(encrypted_data);
    }
    else 
    {
        printk(KERN_INFO "USB Crypto Driver: Successfully submitted encrypted URB\n");
    }


    // Free the URB
    usb_free_urb(urb);
}

// URB completion handler for bulk IN (data received from USB device)
static void usb_crypto_bulk_in_callback(struct urb *urb)
{
    struct usb_crypto *dev = urb->context;
    
    //allow decryption to happen
    // dev->is_encrypting = false;

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
    printk(KERN_INFO "USB Crypto Driver: Key setup initiated\n");

    //set public key
    int ret = set_public_key();
    if (ret)
    {
        printk(KERN_ERR "USB Crypto Driver: Key setup failed: %d\n", ret);
        
        return ret;
    }
    else {
        printk(KERN_INFO "USB Crypto Driver: Key setup successful.\n");
    }

    return usb_register(&usb_crypto_driver);
}

//Module exit
static void __exit usb_crypto_exit(void)
{
    usb_deregister(&usb_crypto_driver);
    if(tfm)
    {
        crypto_free_akcipher(tfm);
    }
    printk(KERN_INFO "USB Crypto Driver: Module unloaded\n");
}

module_init(usb_crypto_init);
module_exit(usb_crypto_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Stephanie Ciprian and Deep Shah");
MODULE_DESCRIPTION("A USB driver that encrypts and decrypts data in C");
