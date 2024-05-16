import Link from 'next/link';
import { HomeIcon, PencilIcon, PlusCircleIcon, ChatIcon, UserIcon } from '@heroicons/react/outline';
import "./styles.css"

const NavBar = () => {
  return (
    <div id="hola" className="fixed inset-x-0 bottom-0 mx-auto max-w-full z-10">
      <div className="flex justify-between items-center px-4 h-14 bg-green-600 rounded-tl-lg rounded-tr-lg"> 
        <Link href="/home" className="z-10">
          <span className="cursor-pointer">
            <HomeIcon className="h-6 w-6 text-white" />
          </span>
        </Link>

        <Link href="/journal" className="z-10">
          <span className="cursor-pointer">
            <PencilIcon className="h-6 w-6 text-white" />
          </span>
        </Link>
        
        <div className="h-6 w-6"></div>
        
        <Link href="/forum" className="z-10">
          <span className="cursor-pointer">
            <ChatIcon className="h-6 w-6 text-white" />
          </span>
        </Link>
        
        <Link href="/profile" className="z-10">
          <span className="cursor-pointer">
            <UserIcon className="h-6 w-6 text-white" />
          </span>
        </Link>
      </div>
      <div className="absolute inset-x-0 bottom-0 flex justify-center pb-4">
        <Link href="/journal/addJournalEntry" className="z-10">
          <span className="cursor-pointer">
            <PlusCircleIcon className="h-12 w-12 text-green-600 bg-white rounded-full shadow" />
          </span>
        </Link>
      </div>
    </div>
  );
};

export default NavBar;
