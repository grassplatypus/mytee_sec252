cp ./out/boot/* /media/`whoami`/boot
sudo cp -r ./out/rootfs/* /media/`whoami`/rootfs
sudo cp ./mytee_examples/myta_fb_mmap/host/myta_fb_mmap_no_ta /media/`whoami`/rootfs/bin
sudo cp ./mytee_examples/myta_fb_write/myta_fb_write_no_ta /media/`whoami`/rootfs/bin
sudo cp ./mytee_examples/toctou_attack/toctou_victim.ko /media/`whoami`/rootfs/root/vic.ko
sudo cp ./mytee_examples/toctou_attack/toctou_attacker.ko /media/`whoami`/rootfs/root/atk.ko
sudo cp ./mytee_examples/tpm_orig/eltt2 /media/`whoami`/rootfs/bin/myta_tpm_no_ta
# TOCTOU user-space attack program
if [ -f ./mytee_examples/toctou_test/toctou_test ]; then
    sudo cp ./mytee_examples/toctou_test/toctou_test /media/`whoami`/rootfs/bin/
fi
cp linux/arch/arm/boot/dts/*.dtb /media/`whoami`/boot
sync
