#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>

#define VENDOR_ID 
#define PRODUCT_ID 


//missing USB interface constants
#define USB_CLASS_MASS_STORAGE 0x86
#define USB_SC_SCSI 0x06
#define USB_PR_BULK

//USB driver struct
static struct usb_driver usb_crypto_driver ={
    .name = "USB Crypto Driver",
    .id_table = usb_table,
    .probe = usb_crypto_probe,
    .disconnect = usb_crypto_disconnect,
};

//Called when the USB device is plugged in and matches this driver
static int usb_crypto_prove(struct usb_interface *interface, const struct usb_device *id)
{
    printk(KERN_INFO "USB Crypto Driver: USB Device inserted \n");
    return 0;
        
}

//called when the USB device is removed
static void usb_crypto_disconnect (struct usb_interface *interface)
{
    printk(KERN_INFO "USB Crypto Driver: USB Device removed\n");
}

//match table for supported devices
static struct usb_device_id usb_table[] = 
{
 {USB_INTERFACE_INFO(USB_CLASS_MASS_STORAGE, USB_SC_SCSI, USB_PR_BULK) },
 {}
}; 
MODULE_DEVICE_TABLE(usb, usb_table)

//Module init
static int __init usb_crypto_init(void)
{
    printk(KERN_INFO "USB Crypto Driver: Module loaded\n")
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

MODULE_AUTHOR("Stephanie Ciprian");
MODULE_DESCRIPTION("A USB driver that encrypts and decrypts data in C")