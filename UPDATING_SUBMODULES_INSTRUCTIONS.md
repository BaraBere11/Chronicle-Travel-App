If you have more than one submodule in your Git repository and you want to update all of them to their latest commits, you can follow these steps:

1. Navigate to the root directory of your main repository:

   ```bash
   cd /path/to/main/repository
   ```

2. Initialize and update all submodules:

   ```bash
   git submodule update --init --recursive --remote
   ```

   This command initializes any uninitialized submodules and updates all submodules to their latest commits.

3. If you want to update only specific submodules, you can use:

   ```bash
   git submodule update --recursive --remote path/to/submodule1 path/to/submodule2
   ```

   Replace `path/to/submodule1`, `path/to/submodule2`, etc., with the paths to the specific submodules you want to update.

4. If the submodules have their own branches, navigate to each submodule's directory:

   ```bash
   cd path/to/submodule1
   git checkout master  # Replace 'master' with the desired branch name
   cd ..

   cd path/to/submodule2
   git checkout master  # Replace 'master' with the desired branch name
   cd ..
   ```

   Repeat this for each submodule you want to update.

5. Go back to the main repository's root directory:

   ```bash
   cd ..
   ```

6. Commit the changes in the main repository to record the new submodule commit hashes:

   ```bash
   git add .
   git commit -m "Update submodules to latest commits"
   git push
   ```

These steps ensure that all submodules in your repository are updated to their latest commits. Adjust the submodule paths and branch names as needed for your specific repository structure.