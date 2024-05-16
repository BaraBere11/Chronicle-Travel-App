import Link from 'next/link';
import { HiOutlineLightBulb } from "react-icons/hi";
import Image from 'next/image';

const TopNavBar = () => {
  return (
    <div className="py-4 px-6 flex items-center pb-1 mb-2 ml-1">
      <Link href="/home" legacyBehavior>
        <div className="flex items-center">

          {/* Logo banner-chronicle-transparent.png*/}
          <Image 
          src="/banner-chronicle-transparent.png" 
          alt="Logo" 
          width={130}
          height={34} className="mr-2" />


        </div>
      </Link>
    </div>
  );
};

export default TopNavBar;
