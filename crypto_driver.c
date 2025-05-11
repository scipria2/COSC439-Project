#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/crypto.h>

#define VENDOR_ID 0x1234
#define PRODUCT_ID 0x5678


//missing USB interface constants
#define USB_CLASS_MASS_STORAGE 0x08
#define USB_SC_SCSI 0x06
#define USB_PR_BULK 0x50

//hardcoded public key (NEEDS TO BE LOADED IN .DER FORMAT... WORK IN PROGRESS)
#define PUBLIC_KEY "-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+NWmIK/0w6mfEeAfduFa32lw8gN133cfFoQKQyIgQv/CuODNuYtL1cgDhmj8yC6FcWAtUrhwlpmy+FFKoUwFS1vV7hozD04PU7/K5ayFQAzg8229FmFcTu4V8biH8JF97LZ481RHN+F1W4Oi5mvl5JoYd955enQERLDHqdPugCQIDAQAB-----END PUBLIC KEY-----"

//match table for supported devices
static struct usb_device_id usb_table[] = 
{
 {USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, USB_PR_BULK) },
 {}
}; 
MODULE_DEVICE_TABLE(usb, usb_table)

// Driver private data structure
struct usb_crypto {
    struct usb_device *udev;
    struct usb_interface *interface;
    unsigned char bulk_in_endpointAddr;
    unsigned char bulk_out_endpointAddr;
};

// Forward declarations for URB completion handlers
static void usb_crypto_bulk_out_callback(struct urb *urb);
static void usb_crypto_bulk_in_callback(struct urb *urb);

// URB completion handler for bulk OUT (data sent to USB device)
static void usb_crypto_bulk_out_callback(struct urb *urb)
{
    // Placeholder for encryption logic before data is sent to USB device
    printk(KERN_INFO "USB Crypto Driver: Bulk OUT URB completed\n");

    // Free the URB
    usb_free_urb(urb);
}

// URB completion handler for bulk IN (data received from USB device)
static void usb_crypto_bulk_in_callback(struct urb *urb)
{
    // Placeholder for decryption logic after data is received from USB device
    printk(KERN_INFO "USB Crypto Driver: Bulk IN URB completed\n");

    // Free the URB
    usb_free_urb(urb);
}

//USB driver struct
static struct usb_driver usb_crypto_driver ={
    .name = "USB Crypto Driver",
    .id_table = usb_table,
    .probe = usb_crypto_probe,
    .disconnect = usb_crypto_disconnect,
};

//Called when the USB device is plugged in and matches this driver
static int usb_crypto_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    struct usb_device *udev = interface_to_usbdev(interface);

    if (udev->descriptor.idVendor == VENDOR_ID && udev->descriptor.idProduct == PRODUCT_ID) {
        printk(KERN_INFO "USB Crypto Driver: Specific USB Device detected (Vendor: %04x, Product: %04x)\n",
               udev->descriptor.idVendor, udev->descriptor.idProduct);

        // Claim the interface
        int retval = usb_driver_claim_interface(&usb_crypto_driver, interface, NULL);
        if (retval) {
            printk(KERN_ERR "USB Crypto Driver: Failed to claim interface\n");
            return retval;
        }

        // TODO: Setup URB interception for bulk transfers here

        // Find bulk IN and OUT endpoints
        struct usb_host_interface *iface_desc = interface->cur_altsetting;
        int i;
        struct usb_crypto *dev;

        dev = kzalloc(sizeof(struct usb_crypto), GFP_KERNEL);
        if (!dev) {
            printk(KERN_ERR "USB Crypto Driver: Cannot allocate memory for usb_crypto\n");
            return -ENOMEM;
        }

        dev->udev = usb_get_dev(interface_to_usbdev(interface));
        dev->interface = interface;

        for (i = 0; i < iface_desc->desc.bNumEndpoints; i++) {
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

        usb_set_intfdata(interface, dev);

        if (dev->bulk_in_endpointAddr) {
            struct urb *urb_in = usb_alloc_urb(0, GFP_KERNEL);
            if (urb_in) {
                unsigned char *buf_in = kmalloc(512, GFP_KERNEL);
                if (buf_in) {
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
    }

    printk(KERN_INFO "USB Crypto Driver: Unsupported USB Device detected\n");
    return -ENODEV;
}

//encryption function (WORK IN PROGRESS)
static int encrypt()
{
    //TODO: encryption function
    struct crypto_akcipher *tfm;
    struct akcipher_request *req;
    struct scatterlist sl;

}

//called when the USB device is removed
static void usb_crypto_disconnect (struct usb_interface *interface)
{
    struct usb_crypto *dev = usb_get_intfdata(interface);

    usb_set_intfdata(interface, NULL);

    if (dev) {
        usb_put_dev(dev->udev);
        kfree(dev);
    }

    usb_driver_release_interface(&usb_crypto_driver, interface);

    printk(KERN_INFO "USB Crypto Driver: USB Device removed\n");
}

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

MODULE_AUTHOR("Stephanie Ciprian and Deep Shah");
MODULE_DESCRIPTION("A USB driver that encrypts and decrypts data in C");
