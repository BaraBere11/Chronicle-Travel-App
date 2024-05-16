import { deleteJournalEntry } from '@/lib/userData';
import React, { useState } from 'react';
import {useRouter} from 'next/navigation';

type Props = {
    showDeleteConfirmation: boolean;
    entryId: string;
}

function DeleteJournalEntryConfirmation(props: Props) {
   
    const [deleteConfirmation, setDeleteConfirmation] = useState(props.showDeleteConfirmation);
    const router = useRouter();

    {/* Juan: clicking on yes will execute the below function and call deleteJournalEntry function with the ID*/}
    const handleDelete = async () => {
        
        await deleteJournalEntry(props.entryId);
        console.log("Delete confirmed");
        
        //redirect to journal page
        router.push('/journal');

    }

    {/* Juan: clicking on NO will make the modal window disappear*/}
    const showDeleteConfirmation = (e: React.MouseEvent<HTMLButtonElement>) => {
        e.preventDefault();
        setDeleteConfirmation(false);
    } 

    return (
        <>
        {
        deleteConfirmation &&
            <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full flex justify-center items-center z-10">
            <div className="bg-white p-5 rounded-lg shadow-xl">
                <h2 className="text-lg font-semibold mb-4 text-center">Confirm Deletion</h2>
                <p className="mb-4 justify-center text-center">Are you sure you want <br/> to delete this entry?</p>
                <div className="flex justify-between">
                    <button onClick={showDeleteConfirmation} className="bg-gray-300 text-gray-700 px-4 py-2 ml-5 rounded hover:bg-gray-400">No</button> 
                    <button onClick={handleDelete} className="bg-red-500 text-white px-4 py-2 mr-5 rounded hover:bg-red-600">Yes</button>
                </div>
            </div>
            </div>
        }
        </>
    )
}

export default DeleteJournalEntryConfirmation
