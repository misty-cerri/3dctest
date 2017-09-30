package org.climbing.web;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.climbing.domain.Person;
import org.climbing.repo.ConfigurationsDao;
import org.climbing.repo.PersonDao;
import org.climbing.util.MailUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping(value="/mailing")
public class MailingController {

	public static final Pattern VALID_EMAIL_ADDRESS_REGEX = 
		    Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,6}$", Pattern.CASE_INSENSITIVE);
	
	@Autowired
	MailUtil mailUtil;
	
	@Autowired
	ConfigurationsDao configurationsDao;
	
	@Autowired
	PersonDao personDao;
	
	@RequestMapping(method=RequestMethod.GET)
    public String load(Model model)
    {
        return "mailing";
    }
	
	@RequestMapping(method=RequestMethod.POST, params = "method=send")
    public String send(HttpServletRequest request, HttpServletResponse response,
			ModelMap model, final RedirectAttributes redirectAttributes)
    {
		String subject = request.getParameter("subject");
		String message = request.getParameter("text");
		String type = request.getParameter("type");
		
		List<String> toListCCN = new ArrayList<String>();
		if("all".equals(type)) {
//			String env = configurationsDao.findByKey("env").getValue();
			String env = System.getProperty("PLATFORM");
			String testEnvAllDest = configurationsDao.findByKey("mailing.test.env.to").getValue();
			List<Person> persons = personDao.findMailingPersons();
			if("dev".equals(env) || "test".equals(env)) {
				toListCCN.add(testEnvAllDest);
			} else {
				for(Person p: persons) {
					Matcher matcher = VALID_EMAIL_ADDRESS_REGEX .matcher(p.getEmail());
					/*
					 * Only valid emails
					 */
			        if(matcher.find()) {
			        	System.out.println("Sending mailing to " + p.getEmail() + " :" + p.getName() + " " + p.getSurname());
			        	toListCCN.add(p.getEmail());
			        } else {
			        	System.out.println("Email not valid: " + p.getEmail());
			        }
				}
			}
		} else {
			String tos = configurationsDao.findByKey("mailing.test.to").getValue();
			if(tos != null) {
				toListCCN = Arrays.asList(tos.split("\\,"));
			}
		}
		
		String fromEmail = configurationsDao.findByKey("smtp.default.from.email").getValue();
		String fromName = configurationsDao.findByKey("smtp.default.from.name").getValue();
		
		String result = "Email inviata a " + toListCCN.size() + " indirizzi";
		try {
			
			mailUtil.sendMail(fromEmail, fromName, null, null, toListCCN, subject, message, null, null, true);
			
		} catch (Exception e) {
			
			System.out.println("Cannot send mailing");
			e.printStackTrace();
			result = "Errore nell'invio della mail";
		}
		
		redirectAttributes.addAttribute("result", result);
        return "redirect:/mailing";
    }
	
}
