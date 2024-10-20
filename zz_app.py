  GNU nano 6.2                                             app.py                                                 M                     setting = AdminSettings(setting_name='num_ads_to_show', setting_value=new_num_ads)
                db.session.add(setting)

            try:
                db.session.commit()
                flash("Settings updated successfully!", "success")
            except Exception as e:
                logging.error(f"Error updating settings: {e}")
                db.session.rollback()
                flash("Failed to update settings. Please try again.", "danger")

    return render_template('admin_settings.html', num_ads_to_show=num_ads_to_show)

@app.route('/')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('signup'))

if __name__ == '__main__':
    app.run(debug=True)


